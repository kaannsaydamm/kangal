// DiagnosticsView — full capability matrix (host + binaries).
//
// Renders the table at the top (platform/WSL/POSIX/admin/python/node/git/docker)
// followed by every binary reported by /api/system/diag, with ✓/✗ + version +
// INSTALL button. Clicking INSTALL opens a streaming log panel below the row.
//
// Layout: full-width, scrollable, dark. The same component is reused inside
// DiagnosticsModal — that's why it doesn't render its own backdrop.

import { useEffect, useRef, useState } from 'react';
import { RefreshCw, Download, Loader2, Check, X, Terminal } from 'lucide-react';

import {
  getSystemDiag,
  startInstall,
  type SystemDiag,
  type SystemDiagBinary,
} from '@/lib/api';
import { InstallStream } from '@/lib/installStream';

interface DiagnosticsViewProps {
  /** Hide the panel chrome (used inside a modal). */
  embedded?: boolean;
}

interface InstallProgress {
  binary: string;
  install_id: string | null;
  status: 'idle' | 'queued' | 'running' | 'ok' | 'failed' | 'skipped' | 'error';
  exit_code?: number | null;
  reason?: string;
  log: string[];
}

// Top-row summary capabilities shown before the binary table.
const HOST_ROWS: { label: string; pick: (d: SystemDiag) => string | boolean | null }[] = [
  { label: 'Platform', pick: (d) => d.host?.system ?? '—' },
  { label: 'Release', pick: (d) => d.host?.release ?? '—' },
  { label: 'Machine', pick: (d) => d.host?.machine ?? '—' },
  { label: 'Python', pick: (d) => d.host?.python_version ?? '—' },
  { label: 'WSL', pick: (d) => (d.host?.is_wsl ? 'yes' : 'no') },
  { label: 'Admin', pick: (d) => (d.host?.is_admin ? 'yes' : 'no') },
];

const CORE_BINS = ['python3', 'node', 'npm', 'git', 'docker', 'bash', 'sh', 'curl', 'wget', 'sudo'];

function checkIcon(present: boolean) {
  return present ? (
    <span className="text-primary font-bold" title="present">
      <Check className="w-3 h-3 inline" />
    </span>
  ) : (
    <span className="text-destructive font-bold" title="missing">
      <X className="w-3 h-3 inline" />
    </span>
  );
}

export function DiagnosticsView({ embedded = false }: DiagnosticsViewProps) {
  const [diag, setDiag] = useState<SystemDiag | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [progress, setProgress] = useState<Record<string, InstallProgress>>({});
  const [activeLog, setActiveLog] = useState<string | null>(null);
  const streamRef = useRef<InstallStream | null>(null);

  const reload = async () => {
    setLoading(true);
    setErr(null);
    try {
      const d = await getSystemDiag();
      setDiag(d);
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
    return () => {
      streamRef.current?.close();
    };
  }, []);

  const bins = diag?.binaries ?? {};
  const binNames = Object.keys(bins).sort();

  const filtered = filter
    ? binNames.filter((n) => n.toLowerCase().includes(filter.toLowerCase()))
    : binNames;

  const presentCount = binNames.filter((n) => bins[n]?.present).length;

  const onInstall = async (name: string) => {
    setActiveLog(name);
    setProgress((prev) => ({
      ...prev,
      [name]: { binary: name, install_id: null, status: 'queued', log: [] },
    }));

    let installId: string;
    try {
      const r = await startInstall(name);
      installId = r.install_id;
      setProgress((prev) => ({
        ...prev,
        [name]: {
          binary: name,
          install_id: installId,
          status: 'running',
          log: [`$ ${r.command_str}`],
        },
      }));
    } catch (e) {
      setProgress((prev) => ({
        ...prev,
        [name]: {
          binary: name,
          install_id: null,
          status: 'error',
          log: [],
          reason: String(e),
        },
      }));
      return;
    }

    // tear down any previous stream before opening a new one
    streamRef.current?.close();
    const stream = new InstallStream(installId);
    streamRef.current = stream;

    stream.addEventListener('log', (ev) => {
      const e = ev as CustomEvent<{ line: string }>;
      setProgress((prev) => {
        const cur = prev[name];
        if (!cur) return prev;
        return { ...prev, [name]: { ...cur, log: [...cur.log, e.detail.line] } };
      });
    });
    stream.addEventListener('done', (ev) => {
      const e = ev as CustomEvent<{ status: 'ok' | 'failed'; exit_code: number | null }>;
      setProgress((prev) => {
        const cur = prev[name];
        if (!cur) return prev;
        return {
          ...prev,
          [name]: { ...cur, status: e.detail.status, exit_code: e.detail.exit_code },
        };
      });
    });
    stream.addEventListener('error', (ev) => {
      const e = ev as CustomEvent<{ message: string }>;
      setProgress((prev) => {
        const cur = prev[name];
        if (!cur) return prev;
        return { ...prev, [name]: { ...cur, status: 'error', reason: e.detail.message } };
      });
    });

    stream.connect();
  };

  const rowBg = (present: boolean) =>
    present ? '' : 'bg-destructive/5';

  return (
    <div className={`flex flex-col h-full min-h-0 ${embedded ? '' : 'p-3 gap-3'}`}>
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-primary" />
          <span className="text-sm font-mono text-white tracking-widest uppercase">
            Capability Matrix
          </span>
          {diag && (
            <span className="text-[10px] font-mono text-gray-500">
              {diag.summary.present}/{diag.summary.total} PRESENT
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="filter…"
            className="text-[10px] font-mono bg-surface border border-border rounded px-2 py-1 text-gray-200 w-40 placeholder:text-gray-600"
          />
          <button
            onClick={reload}
            disabled={loading}
            className="text-[10px] font-mono px-2 py-1 rounded border border-border bg-surface text-gray-300 hover:bg-surface/60 flex items-center gap-1 disabled:opacity-40"
          >
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            RE-DETECT
          </button>
        </div>
      </div>

      {err && (
        <div className="text-[11px] font-mono text-destructive">ERR: {err}</div>
      )}

      {/* Host summary table */}
      {diag && (
        <div className="border border-border rounded bg-surface/40 p-2">
          <div className="text-[10px] font-mono text-gray-500 uppercase mb-1">Host</div>
          <table className="w-full text-[11px] font-mono">
            <tbody>
              {HOST_ROWS.map((r) => (
                <tr key={r.label} className="border-b border-border/40 last:border-0">
                  <td className="py-1 pr-3 text-gray-400 w-24">{r.label}</td>
                  <td className="py-1 text-gray-200">{String(r.pick(diag) ?? '—')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Core binaries row */}
      {diag && (
        <div className="border border-border rounded bg-surface/40 p-2">
          <div className="text-[10px] font-mono text-gray-500 uppercase mb-1">Core</div>
          <div className="grid grid-cols-5 gap-1 text-[11px] font-mono">
            {CORE_BINS.map((n) => {
              const b = bins[n];
              return (
                <div
                  key={n}
                  className={`flex items-center justify-between px-2 py-1 rounded border border-border/40 ${rowBg(!!b?.present)}`}
                >
                  <span className="text-gray-300 truncate">{n}</span>
                  <span className="text-gray-500 truncate ml-1">
                    {checkIcon(!!b?.present)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Full binary table */}
      <div className="flex-1 min-h-0 overflow-y-auto border border-border rounded bg-surface/40">
        <table className="w-full text-[11px] font-mono">
          <thead className="sticky top-0 bg-[#0a0a0a] z-10">
            <tr className="text-left text-gray-500 border-b border-border">
              <th className="px-2 py-1.5 font-medium">BINARY</th>
              <th className="px-2 py-1.5 font-medium w-12">STATE</th>
              <th className="px-2 py-1.5 font-medium">VERSION</th>
              <th className="px-2 py-1.5 font-medium">INSTALL CMD</th>
              <th className="px-2 py-1.5 font-medium w-20 text-right">ACTION</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((name) => {
              const b = bins[name] as SystemDiagBinary;
              const prog = progress[name];
              const status = prog?.status || 'idle';
              return (
                <tr key={name} className={`border-b border-border/30 ${rowBg(!!b?.present)}`}>
                  <td className="px-2 py-1 text-gray-200">{name}</td>
                  <td className="px-2 py-1">{checkIcon(!!b?.present)}</td>
                  <td className="px-2 py-1 text-gray-500 truncate max-w-[120px]" title={b?.version ?? ''}>
                    {b?.version || (b?.present ? '?' : '—')}
                  </td>
                  <td
                    className="px-2 py-1 text-gray-500 truncate max-w-[260px]"
                    title={b?.install_cmd ?? ''}
                  >
                    {b?.install_cmd || (b?.present ? '' : <span className="text-gray-700">—</span>)}
                  </td>
                  <td className="px-2 py-1 text-right">
                    {b?.present ? (
                      <span className="text-[10px] text-primary font-bold">OK</span>
                    ) : status === 'running' || status === 'queued' ? (
                      <span className="text-[10px] text-yellow-400 font-bold flex items-center justify-end gap-1">
                        <Loader2 className="w-3 h-3 animate-spin" /> {status.toUpperCase()}
                      </span>
                    ) : status === 'ok' ? (
                      <span className="text-[10px] text-primary font-bold">DONE</span>
                    ) : status === 'failed' ? (
                      <span className="text-[10px] text-destructive font-bold">FAIL</span>
                    ) : (
                      <button
                        onClick={() => onInstall(name)}
                        disabled={!b?.install_cmd}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 disabled:opacity-30 disabled:cursor-not-allowed inline-flex items-center gap-1"
                      >
                        <Download className="w-3 h-3" /> INSTALL
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && diag && (
              <tr>
                <td colSpan={5} className="text-center py-3 text-gray-600 text-[11px]">
                  no binaries match filter
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Streaming install log */}
      {activeLog && progress[activeLog] && (
        <div className="border border-border rounded bg-black/60">
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-border">
            <div className="flex items-center gap-2 text-[10px] font-mono">
              <Terminal className="w-3 h-3 text-primary" />
              <span className="text-gray-400">install log:</span>
              <span className="text-primary">{activeLog}</span>
              <span
                className={`ml-2 ${
                  progress[activeLog].status === 'ok'
                    ? 'text-primary'
                    : progress[activeLog].status === 'failed'
                      ? 'text-destructive'
                      : progress[activeLog].status === 'error'
                        ? 'text-destructive'
                        : 'text-yellow-400'
                }`}
              >
                {progress[activeLog].status.toUpperCase()}
              </span>
            </div>
            <button
              onClick={() => {
                streamRef.current?.close();
                streamRef.current = null;
                setActiveLog(null);
              }}
              className="text-[10px] font-mono text-gray-500 hover:text-gray-200"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
          <pre className="text-[10px] font-mono text-gray-300 p-2 max-h-48 overflow-y-auto whitespace-pre-wrap break-all">
            {progress[activeLog].log.join('\n') || '(no output yet)'}
          </pre>
        </div>
      )}

      {diag && (
        <div className="text-[9px] font-mono text-gray-600">
          platform_id={diag.host.platform_id} · present={presentCount}/{binNames.length}
        </div>
      )}
    </div>
  );
}
