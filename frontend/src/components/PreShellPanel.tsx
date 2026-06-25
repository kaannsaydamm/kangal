// PreShellPanel — capability gate shown before the PTY bash session opens.
// Surfaces:
//   - host platform + WSL/admin state
//   - POSIX availability (native Windows vs Linux/macOS/WSL)
//   - shell presence (bash or powershell.exe)
//   - common recon tools (nmap, nuclei, httpx, sqlmap, ffuf, bloodhound-python,
//     msfconsole, ghidra) with INSTALL buttons + WS-streamed install log.
//
// The bottom CTA depends on platform state:
//   - POSIX available (Linux/macOS/WSL)         -> [LAUNCH SHELL]
//   - native Windows + WSL detected             -> [OPEN WSL SHELL]
//   - native Windows + no WSL                   -> install guide only
//   - everything critical missing on Linux      -> LAUNCH SHELL still enabled
//
// Safety: this panel refuses to call onLaunch() when POSIX is unavailable
// on native Windows and WSL wasn't selected — the user must explicitly
// choose the WSL route or read the install guide.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  Loader2,
  Play,
  RefreshCw,
  Terminal as TerminalIcon,
  XCircle,
} from 'lucide-react';

import {
  type SystemDiag,
  type SystemDiagBinary,
  getSystemDiag,
  startInstall,
} from '@/lib/api';
import { InstallStream } from '@/lib/installStream';

interface PreShellPanelProps {
  onLaunch: () => void;
  onClose?: () => void;
}

// Tools shown in the capability matrix. Order = display order.
const RECON_TOOLS: string[] = [
  'nmap',
  'nuclei',
  'httpx',
  'sqlmap',
  'ffuf',
  'bloodhound-python',
  'msfconsole',
  'ghidra',
];

type HostKind = 'linux' | 'macos' | 'wsl' | 'windows';

function classifyHost(diag: SystemDiag | null): HostKind {
  if (!diag) return 'windows';
  const sys = (diag.host.system || '').toLowerCase();
  if (diag.host.is_wsl) return 'wsl';
  if (sys === 'linux') return 'linux';
  if (sys === 'darwin') return 'macos';
  return 'windows';
}

function hasPosix(host: HostKind): boolean {
  return host === 'linux' || host === 'macos' || host === 'wsl';
}

function platformLabel(host: HostKind, raw?: string): string {
  if (host === 'wsl') return 'Windows Subsystem for Linux';
  if (host === 'linux') return `Linux (${raw || 'POSIX'})`;
  if (host === 'macos') return 'macOS / Darwin';
  return `Windows (${raw || 'native'})`;
}

export function PreShellPanel({ onLaunch, onClose }: PreShellPanelProps) {
  const [diag, setDiag] = useState<SystemDiag | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Per-binary install state.
  const [installBusy, setInstallBusy] = useState<Record<string, boolean>>({});
  const [installLogs, setInstallLogs] = useState<Record<string, string[]>>({});
  const [installStatus, setInstallStatus] = useState<Record<string, 'running' | 'ok' | 'failed' | 'error'>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const streamsRef = useRef<Record<string, InstallStream>>({});

  const refetch = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await getSystemDiag();
      setDiag(d);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refetch();
    return () => {
      // Detach any open install streams.
      Object.values(streamsRef.current).forEach((s) => s.close());
      streamsRef.current = {};
    };
  }, [refetch]);

  const host = useMemo(() => classifyHost(diag), [diag]);
  const posix = hasPosix(host);

  const posixBinary = diag?.binaries?.posix;
  const bashBinary = diag?.binaries?.bash;
  const psBinary = diag?.binaries?.powershell;

  // ----- install a missing binary -----
  const onInstall = useCallback(
    async (name: string) => {
      setInstallBusy((m) => ({ ...m, [name]: true }));
      setInstallStatus((m) => ({ ...m, [name]: 'running' }));
      setInstallLogs((m) => ({ ...m, [name]: [] }));
      setExpanded((m) => ({ ...m, [name]: true }));
      try {
        const r = await startInstall(name);
        const stream = new InstallStream(r.install_id);
        streamsRef.current[name] = stream;
        stream.addEventListener('log', (ev) => {
          const e = ev as CustomEvent<{ line: string }>;
          setInstallLogs((m) => ({
            ...m,
            [name]: [...(m[name] || []), e.detail.line].slice(-200),
          }));
        });
        stream.addEventListener('done', (ev) => {
          const e = ev as CustomEvent<{ status: 'ok' | 'failed' }>;
          setInstallStatus((m) => ({ ...m, [name]: e.detail.status }));
          setInstallBusy((m) => ({ ...m, [name]: false }));
          // Refresh diag once an install finishes so the row flips to "present".
          if (e.detail.status === 'ok') {
            void refetch();
          }
        });
        stream.addEventListener('error', (ev) => {
          const e = ev as CustomEvent<{ message: string }>;
          setInstallStatus((m) => ({ ...m, [name]: 'error' }));
          setInstallLogs((m) => ({
            ...m,
            [name]: [...(m[name] || []), `[error] ${e.detail.message}`],
          }));
          setInstallBusy((m) => ({ ...m, [name]: false }));
        });
        stream.connect();
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        setInstallStatus((m) => ({ ...m, [name]: 'error' }));
        setInstallLogs((m) => ({
          ...m,
          [name]: [...(m[name] || []), `[error] ${msg}`],
        }));
        setInstallBusy((m) => ({ ...m, [name]: false }));
      }
    },
    [refetch]
  );

  const toggleExpand = useCallback((name: string) => {
    setExpanded((m) => ({ ...m, [name]: !m[name] }));
  }, []);

  // ----- bottom-CTA branching -----
  const reconSummary = useMemo(() => {
    const present = RECON_TOOLS.filter((n) => diag?.binaries?.[n]?.present).length;
    return { present, total: RECON_TOOLS.length };
  }, [diag]);

  const onLaunchShell = useCallback(() => {
    // Safety: refuse to launch unless POSIX is available on this host.
    if (!posix && host === 'windows') return;
    onLaunch();
  }, [posix, host, onLaunch]);

  const openInstallGuide = useCallback(() => {
    window.open('/INSTALL.md', '_blank', 'noopener,noreferrer');
  }, []);

  return (
    <div className="flex flex-col h-full border border-border rounded-lg overflow-hidden bg-background shadow">
      {/* Top bar */}
      <div className="bg-surface border-b border-border px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <TerminalIcon className="w-4 h-4 text-primary" />
          <span className="text-xs font-mono text-gray-200">
            Pre-Flight Shell Diagnostic
          </span>
          <span className="text-[10px] font-mono text-gray-500 uppercase">
            {loading ? 'probing…' : diag ? `${diag.summary.present}/${diag.summary.total} ready` : '—'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void refetch()}
            disabled={loading}
            className="text-[10px] font-mono px-2 py-1 rounded bg-surface text-gray-400 border border-border hover:bg-surface/60 disabled:opacity-50 flex items-center gap-1"
            title="Re-run system diagnostic"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
            RE-DETECT
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="text-[10px] font-mono px-2 py-1 rounded bg-surface text-gray-400 border border-border hover:bg-surface/60"
              title="Hide the pre-flight panel"
            >
              HIDE
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4">
        {error && (
          <div className="text-[11px] font-mono text-red-400 border border-red-700/50 bg-red-900/20 rounded px-3 py-2 flex items-start gap-2">
            <AlertCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
            <span>Diagnostic failed: {error}</span>
          </div>
        )}

        {/* Host + POSIX + Shell */}
        <Section title="Host">
          <CapabilityRow
            icon={<CheckCircle2 className="w-4 h-4 text-green-500" />}
            label="Platform"
            value={platformLabel(host, diag?.host.system)}
            subValue={
              diag
                ? `${diag.host.release || ''} • ${diag.host.machine || ''} • py${diag.host.python_version || ''}`
                : undefined
            }
          />
          <CapabilityRow
            icon={
              diag?.host.is_wsl ? (
                <CheckCircle2 className="w-4 h-4 text-green-500" />
              ) : diag?.host.is_admin ? (
                <CheckCircle2 className="w-4 h-4 text-green-500" />
              ) : (
                <AlertCircle className="w-4 h-4 text-yellow-500" />
              )
            }
            label={diag?.host.is_wsl ? 'WSL' : 'Privileges'}
            value={
              diag?.host.is_wsl
                ? 'WSL detected'
                : diag?.host.is_admin
                  ? 'admin / root'
                  : 'unprivileged'
            }
          />
          <CapabilityRow
            icon={
              posix ? (
                <CheckCircle2 className="w-4 h-4 text-green-500" />
              ) : (
                <XCircle className="w-4 h-4 text-red-500" />
              )
            }
            label="POSIX layer"
            value={posix ? 'available' : 'unavailable on native Windows'}
            subValue={posixBinary?.version || undefined}
          />
          <CapabilityRow
            icon={
              bashBinary?.present ? (
                <CheckCircle2 className="w-4 h-4 text-green-500" />
              ) : psBinary?.present ? (
                <CheckCircle2 className="w-4 h-4 text-yellow-500" />
              ) : (
                <XCircle className="w-4 h-4 text-red-500" />
              )
            }
            label={posix ? 'bash' : 'powershell.exe'}
            value={
              bashBinary?.present
                ? `${bashBinary.path || 'bash'}`
                : psBinary?.present
                  ? `${psBinary.path || 'powershell.exe'}`
                  : 'not found'
            }
            subValue={bashBinary?.version || psBinary?.version || undefined}
          />
        </Section>

        {/* Recon tools */}
        <Section title={`Recon Tools (${reconSummary.present}/${reconSummary.total} ready)`}>
          {RECON_TOOLS.map((name) => (
            <ToolRow
              key={name}
              name={name}
              bin={diag?.binaries?.[name] || null}
              busy={!!installBusy[name]}
              status={installStatus[name] || null}
              logs={installLogs[name] || []}
              expanded={!!expanded[name]}
              onInstall={() => void onInstall(name)}
              onToggleExpand={() => toggleExpand(name)}
            />
          ))}
        </Section>
      </div>

      {/* Bottom CTA */}
      <div className="border-t border-border bg-surface px-4 py-3 space-y-2">
        {posix ? (
          reconSummary.present === reconSummary.total ? null : (
            <div className="text-[10px] font-mono text-yellow-400">
              Your bash toolchain is healthy, but recon tools are missing. Install them above to get the most out of the shell.
            </div>
          )
        ) : host === 'windows' && diag?.host.is_wsl ? (
          <div className="text-[10px] font-mono text-yellow-400">
            POSIX is available inside WSL. Launch a WSL bash session for the interactive shell.
          </div>
        ) : host === 'windows' ? (
          <div className="text-[10px] font-mono text-red-400">
            POSIX not available on this host. Either install WSL2 (recommended) or run the backend in Docker/Linux. See INSTALL.md for setup.
          </div>
        ) : null}

        {posix ? (
          <button
            onClick={onLaunchShell}
            className="w-full bg-primary text-primary-foreground hover:bg-primary/90 rounded px-4 py-3 text-sm font-mono flex items-center justify-center gap-2 glow-primary"
          >
            <Play className="w-4 h-4" />
            LAUNCH SHELL
          </button>
        ) : host === 'windows' && diag?.host.is_wsl ? (
          <button
            onClick={openInstallGuide}
            className="w-full bg-yellow-600/80 text-yellow-50 hover:bg-yellow-600 rounded px-4 py-3 text-sm font-mono flex items-center justify-center gap-2"
            title="Open INSTALL.md in a new tab"
          >
            <BookOpen className="w-4 h-4" />
            OPEN WSL SHELL GUIDE
          </button>
        ) : host === 'windows' ? (
          <button
            onClick={openInstallGuide}
            className="w-full bg-yellow-600/80 text-yellow-50 hover:bg-yellow-600 rounded px-4 py-3 text-sm font-mono flex items-center justify-center gap-2"
            title="Open INSTALL.md in a new tab"
          >
            <ExternalLink className="w-4 h-4" />
            OPEN INSTALL GUIDE
          </button>
        ) : null}
      </div>
    </div>
  );
}

// ---------- internal sub-components ----------

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-mono uppercase text-gray-500 mb-2 tracking-wider">
        {title}
      </div>
      <div className="border border-border rounded bg-surface/40 divide-y divide-border">
        {children}
      </div>
    </div>
  );
}

function CapabilityRow({
  icon,
  label,
  value,
  subValue,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  subValue?: string;
}) {
  return (
    <div className="flex items-center gap-3 px-3 py-2">
      <div className="shrink-0">{icon}</div>
      <div className="flex-1 min-w-0">
        <div className="text-[11px] font-mono text-gray-300">{label}</div>
        <div className="text-[10px] font-mono text-gray-500 truncate" title={value}>
          {value}
        </div>
      </div>
      {subValue && (
        <div className="text-[10px] font-mono text-gray-400 truncate max-w-[40%]" title={subValue}>
          {subValue}
        </div>
      )}
    </div>
  );
}

function ToolRow({
  name,
  bin,
  busy,
  status,
  logs,
  expanded,
  onInstall,
  onToggleExpand,
}: {
  name: string;
  bin: SystemDiagBinary | null;
  busy: boolean;
  status: 'running' | 'ok' | 'failed' | 'error' | null;
  logs: string[];
  expanded: boolean;
  onInstall: () => void;
  onToggleExpand: () => void;
}) {
  const present = !!bin?.present;
  const version = bin?.version || '';
  const showLog = expanded && (logs.length > 0 || status === 'running');

  return (
    <div>
      <div className="flex items-center gap-3 px-3 py-2">
        <div className="shrink-0">
          {present ? (
            <CheckCircle2 className="w-4 h-4 text-green-500" />
          ) : (
            <XCircle className="w-4 h-4 text-red-500" />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[11px] font-mono text-gray-200">{name}</div>
          <div className="text-[10px] font-mono text-gray-500 truncate" title={bin?.path || ''}>
            {present
              ? bin?.path || 'present'
              : status === 'failed' || status === 'error'
                ? 'install failed'
                : status === 'running'
                  ? 'installing…'
                  : 'not installed'}
          </div>
        </div>
        <div className="text-[10px] font-mono text-gray-400 truncate max-w-[30%]" title={version}>
          {version}
        </div>
        <div className="shrink-0">
          {present ? null : (
            <button
              onClick={onInstall}
              disabled={busy}
              className="text-[10px] font-mono px-2 py-1 rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 flex items-center gap-1"
              title={`Install ${name}`}
            >
              {busy ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Download className="w-3 h-3" />
              )}
              INSTALL
            </button>
          )}
        </div>
        <button
          onClick={onToggleExpand}
          className="shrink-0 text-gray-500 hover:text-gray-300"
          title={expanded ? 'Collapse log' : 'Expand log'}
          disabled={!showLog && !logs.length && status !== 'running'}
        >
          {(expanded && (logs.length > 0 || status === 'running')) ? (
            <ChevronDown className="w-3.5 h-3.5" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5" />
          )}
        </button>
      </div>
      {showLog && (
        <div className="px-3 pb-3">
          <pre className="text-[10px] font-mono text-gray-400 bg-background/80 border border-border rounded p-2 max-h-40 overflow-y-auto whitespace-pre-wrap break-all">
            {logs.length === 0 && status === 'running' ? '[install starting…]' : logs.join('\n')}
            {status === 'running' && <span className="animate-pulse">▌</span>}
          </pre>
        </div>
      )}
    </div>
  );
}