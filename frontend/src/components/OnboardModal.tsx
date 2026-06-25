// OnboardModal — 6-step first-run wizard.
//
// Step 1 WELCOME  intro + GET STARTED / SKIP
// Step 2 DETECT   auto-runs GET /api/system/diag (10s timeout), shows results
// Step 3 CHOOSE   3 radio cards (native / wsl / skip) → POST choose-path
// Step 4 CONSENT  user must type "yes i consent" → POST consent
// Step 5 INSTALL  POST install + per-binary WS /ws/install/{id} stream
// Step 6 DONE     POST finish + set localStorage flag + close
//
// The flag is keyed "kangal.onboarded.v2". useOnboardFlag() returns
// [open, reopen, setOpen] matching the previous shape so App.tsx doesn't
// need to change.

import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { ChevronLeft, X, Check, Loader2 } from 'lucide-react';

import {
  getSystemDiag,
  getOnboardState,
  onboardChoosePath,
  onboardConsent,
  onboardInstall,
  onboardFinish,
  type OnboardPath,
  type OnboardInstallEntry,
  type SystemDiag,
  type SystemDiagBinary,
} from '@/lib/api';

const STORAGE_KEY = 'kangal.onboarded.v2';

type StepId = 1 | 2 | 3 | 4 | 5 | 6;
const STEPS_TOTAL = 6;

// Tools we want to know about in the DETECT step.
const CORE_TOOLS = [
  'python3',
  'node',
  'git',
  'docker',
] as const;
const RED_TEAM_TOOLS = [
  'nmap',
  'nuclei',
  'httpx',
  'ffuf',
  'sqlmap',
  'impacket-secretsdump', // binary exposed by impacket-scripts package
  'bloodhound-python',
  'msfconsole',
  'ghidra',
  'sliver',
] as const;

// ---------- helpers ----------

interface InstallProgress {
  binary: string;
  install_id: string | null;
  status: 'queued' | 'running' | 'ok' | 'failed' | 'skipped';
  exit_code?: number;
  reason?: string;
  log: string[];
}

function checkMark(b: SystemDiagBinary | null | undefined): boolean {
  return !!(b && b.present);
}

function checkIcon(present: boolean) {
  return present ? (
    <span className="text-primary font-bold" aria-label="present">
      ✓
    </span>
  ) : (
    <span className="text-destructive font-bold" aria-label="missing">
      ✗
    </span>
  );
}

// ---------- main component ----------

interface OnboardModalProps {
  /** When true, the modal is shown (e.g. via the `?` button). */
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function OnboardModal({ open, onOpenChange }: OnboardModalProps) {
  const [step, setStep] = useState<StepId>(1);
  // localStorage flag is the source of truth; we set it lazily in DONE / SKIP.
  const setClosedFlag = () => {
    try {
      localStorage.setItem(STORAGE_KEY, '1');
    } catch {
      /* ignore */
    }
  };

  const close = () => {
    onOpenChange(false);
  };

  // Reset to step 1 every time the modal re-opens.
  useEffect(() => {
    if (open) setStep(1);
  }, [open]);

  // Esc counts as "I'll look around" — close but keep flag unset so the
  // ? button can reopen (matching previous behavior).
  const onEscape = () => {
    onOpenChange(false);
  };

  const progressPct = Math.round(((step - 1) / (STEPS_TOTAL - 1)) * 100);

  // ---- shared step header (rendered by every step) ----
  const header = (
    <div className="flex items-center justify-between border-b border-border px-5 py-3">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">
          STEP {step}/{STEPS_TOTAL}
        </span>
        <span className="text-gray-700">|</span>
        <span className="text-sm font-mono text-primary uppercase tracking-widest">
          {STEP_TITLES[step]}
        </span>
      </div>
      <Dialog.Close asChild>
        <button
          aria-label="Close"
          onClick={close}
          className="text-gray-500 hover:text-gray-200"
        >
          <X className="w-4 h-4" />
        </button>
      </Dialog.Close>
    </div>
  );

  // ---- shared footer (back / primary action) ----
  const back = (
    <button
      onClick={() => setStep((s) => (Math.max(1, s - 1) as StepId))}
      disabled={step === 1}
      className="text-[10px] font-mono px-3 py-1.5 rounded border border-border bg-surface text-gray-400 hover:bg-surface/60 disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-1"
    >
      <ChevronLeft className="w-3 h-3" /> BACK
    </button>
  );

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 w-[min(720px,92vw)] max-h-[90vh] -translate-x-1/2 -translate-y-1/2 border border-border rounded-lg bg-[#0a0a0a] shadow-2xl outline-none flex flex-col overflow-hidden"
          onEscapeKeyDown={onEscape}
        >
          {header}

          {/* progress bar */}
          <div className="h-1 w-full bg-surface">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${progressPct}%` }}
            />
          </div>

          <div className="px-5 py-5 text-sm text-gray-300 leading-relaxed font-mono overflow-y-auto flex-1">
            {step === 1 && (
              <StepWelcome
                onGetStarted={() => setStep(2)}
                onSkip={() => {
                  setClosedFlag();
                  close();
                }}
              />
            )}
            {step === 2 && (
              <StepDetect
                onContinue={() => setStep(3)}
                backButton={back}
              />
            )}
            {step === 3 && (
              <StepChoose
                onContinue={(next) => setStep(next)}
                backButton={back}
              />
            )}
            {step === 4 && <StepConsent backButton={back} onConsent={() => setStep(5)} />}
            {step === 5 && <StepInstall onDone={() => setStep(6)} />}
            {step === 6 && (
              <StepDone
                onFinish={() => {
                  setClosedFlag();
                  close();
                }}
              />
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ---------- step titles ----------

const STEP_TITLES: Record<StepId, string> = {
  1: 'Welcome',
  2: 'Detect',
  3: 'Choose Path',
  4: 'Consent',
  5: 'Install',
  6: 'Done',
};

// ---------- STEP 1 — WELCOME ----------

function StepWelcome({
  onGetStarted,
  onSkip,
}: {
  onGetStarted: () => void;
  onSkip: () => void;
}) {
  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold text-white tracking-wide">
        Welcome to Kangal
      </h2>
      <p className="text-sm text-gray-300 leading-relaxed">
        Multi-stage threat intelligence for authorized red team engagements. We
        need to set up your environment. This takes about 60 seconds.
      </p>
      <div className="flex items-center gap-2 pt-2">
        <button
          onClick={onGetStarted}
          className="text-xs font-mono px-4 py-2 rounded bg-primary text-black hover:opacity-90 flex items-center gap-2 font-bold tracking-wider"
        >
          <Check className="w-4 h-4" /> GET STARTED
        </button>
        <button
          onClick={onSkip}
          className="text-xs font-mono px-4 py-2 rounded border border-border bg-surface text-gray-400 hover:bg-surface/60 tracking-wider"
        >
          SKIP
        </button>
      </div>
    </div>
  );
}

// ---------- STEP 2 — DETECT ----------

function StepDetect({
  onContinue,
  backButton,
}: {
  onContinue: () => void;
  backButton: React.ReactNode;
}) {
  const [diag, setDiag] = useState<SystemDiag | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [state, setState] = useState<{
    recommendations: string[];
  } | null>(null);
  const [loading, setLoading] = useState(true);

  // Auto-run on mount.
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [d, s] = await Promise.all([
          getSystemDiag(),
          getOnboardState().catch(() => null),
        ]);
        if (!alive) return;
        setDiag(d);
        if (s) setState({ recommendations: s.detected.recommendations || [] });
        setLoading(false);
      } catch (e) {
        if (!alive) return;
        setError(String(e));
        setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const bins = diag?.binaries ?? {};
  const host = diag?.host;

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-bold text-white tracking-wide">
        Detecting your environment
      </h2>

      {loading && (
        <div className="flex items-center gap-2 text-xs text-gray-400 font-mono">
          <Loader2 className="w-4 h-4 animate-spin text-primary" />
          Probing host capabilities (10s timeout)…
        </div>
      )}

      {error && (
        <div className="text-destructive text-xs font-mono">
          {error}
        </div>
      )}

      {diag && (
        <>
          <table className="w-full text-[11px] font-mono border-collapse">
            <thead>
              <tr className="text-gray-500 border-b border-border">
                <th className="text-left py-1 px-2 font-medium">CAPABILITY</th>
                <th className="text-left py-1 px-2 font-medium">STATE</th>
                <th className="text-left py-1 px-2 font-medium">VERSION</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-border/60">
                <td className="py-1 px-2 text-gray-300">Platform</td>
                <td className="py-1 px-2 text-gray-200">
                  {host?.system ?? '—'}
                </td>
                <td className="py-1 px-2 text-gray-500">
                  {host?.release ?? ''}
                </td>
              </tr>
              {host?.system === 'Windows' && (
                <tr className="border-b border-border/60">
                  <td className="py-1 px-2 text-gray-300">WSL</td>
                  <td className="py-1 px-2">
                    {host.is_wsl ? (
                      <span className="text-primary">yes</span>
                    ) : (
                      <span className="text-gray-400">no</span>
                    )}
                  </td>
                  <td className="py-1 px-2 text-gray-500">—</td>
                </tr>
              )}
              {CORE_TOOLS.map((name) => {
                const b = bins[name];
                return (
                  <tr key={name} className="border-b border-border/60">
                    <td className="py-1 px-2 text-gray-300">{name}</td>
                    <td className="py-1 px-2">
                      {checkIcon(checkMark(b))}
                    </td>
                    <td className="py-1 px-2 text-gray-500">
                      {b?.version ?? (b?.present ? '?' : '—')}
                    </td>
                  </tr>
                );
              })}
              {RED_TEAM_TOOLS.map((name) => {
                const b = bins[name];
                return (
                  <tr key={name} className="border-b border-border/60">
                    <td className="py-1 px-2 text-gray-300">{name}</td>
                    <td className="py-1 px-2">
                      {checkIcon(checkMark(b))}
                    </td>
                    <td className="py-1 px-2 text-gray-500">
                      {b?.version ?? (b?.present ? '?' : '—')}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {state && state.recommendations.length > 0 && (
            <div className="mt-4">
              <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest mb-2">
                What we'll install
              </div>
              <ul className="list-disc pl-5 space-y-1 text-xs font-mono text-gray-300">
                {state.recommendations.map((r) => (
                  <li key={r}>
                    <span className="text-primary">{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            {backButton}
            <button
              onClick={onContinue}
              className="text-xs font-mono px-4 py-2 rounded bg-primary text-black hover:opacity-90 font-bold tracking-wider"
            >
              CONTINUE
            </button>
          </div>
        </>
      )}
    </div>
  );
}

// ---------- STEP 3 — CHOOSE PATH ----------

function StepChoose({
  onContinue,
  backButton,
}: {
  onContinue: (next: StepId) => void;
  backButton: React.ReactNode;
}) {
  const [selected, setSelected] = useState<OnboardPath | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!selected) return;
    setSubmitting(true);
    setError(null);
    try {
      const next = await onboardChoosePath(selected);
      // skip → backend sets completed:true → jump straight to DONE.
      if (next.completed) {
        onContinue(6);
      } else {
        onContinue(4);
      }
    } catch (e) {
      setError(String(e));
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-bold text-white tracking-wide">
        How do you want to install the missing tools?
      </h2>

      <div className="grid grid-cols-1 gap-2">
        <PathCard
          id="native"
          selected={selected === 'native'}
          onSelect={() => setSelected('native')}
          title="Native"
          tagline="Recommended on Linux / macOS / WSL"
          body="Runs apt / brew / dnf directly on the host. Fastest path."
        />
        <PathCard
          id="wsl"
          selected={selected === 'wsl'}
          onSelect={() => setSelected('wsl')}
          title="WSL"
          tagline="Windows users"
          body="Install WSL2 first, then run native installers inside WSL."
        />
        <PathCard
          id="skip"
          selected={selected === 'skip'}
          onSelect={() => setSelected('skip')}
          title="Skip"
          tagline="Just looking"
          body="Use the dashboard as-is. Install later from the Toolbox page."
        />
      </div>

      {error && (
        <div className="text-destructive text-xs font-mono">{error}</div>
      )}

      <div className="flex items-center justify-between pt-2">
        {backButton}
        <button
          onClick={submit}
          disabled={!selected || submitting}
          className="text-xs font-mono px-4 py-2 rounded bg-primary text-black hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed font-bold tracking-wider flex items-center gap-2"
        >
          {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
          CONTINUE
        </button>
      </div>
    </div>
  );
}

function PathCard({
  id,
  selected,
  onSelect,
  title,
  tagline,
  body,
}: {
  id: OnboardPath;
  selected: boolean;
  onSelect: () => void;
  title: string;
  tagline: string;
  body: string;
}) {
  return (
    <label
      className={`block cursor-pointer border rounded-lg p-3 transition-colors ${
        selected
          ? 'border-primary bg-primary/5'
          : 'border-border bg-surface/40 hover:border-gray-600'
      }`}
    >
      <div className="flex items-start gap-3">
        <input
          type="radio"
          name="onboard-path"
          value={id}
          checked={selected}
          onChange={onSelect}
          className="mt-1 accent-primary"
        />
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-white">{title}</span>
            <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">
              {tagline}
            </span>
          </div>
          <div className="text-xs text-gray-400 mt-1">{body}</div>
        </div>
      </div>
    </label>
  );
}

// ---------- STEP 4 — CONSENT ----------

function StepConsent({
  backButton,
  onConsent,
}: {
  backButton: React.ReactNode;
  onConsent: () => void;
}) {
  const [text, setText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lowered = text.toLowerCase();
  const valid = lowered.includes('yes') && lowered.includes('consent');

  const submit = async () => {
    if (!valid || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await onboardConsent(text);
      // hop to step 5
      onConsent();
    } catch (e) {
      setError(String(e));
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-bold text-white tracking-wide">
        Explicit consent required
      </h2>
      <p className="text-xs text-gray-300 leading-relaxed">
        Kangal runs offensive security tools. Only scan targets you have a
        signed scope-of-work for. Unauthorized scanning may violate CFAA,
        GDPR, Türk Ceza Kanunu m.243-245, and equivalent laws.
      </p>

      <input
        type="text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="type: yes i consent"
        className="w-full bg-[#0a0a0a] border border-border rounded px-3 py-2 text-sm font-mono text-primary placeholder:text-gray-600 focus:outline-none focus:border-primary"
        spellCheck={false}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
      />

      {error && (
        <div className="text-destructive text-xs font-mono">{error}</div>
      )}

      <div className="flex items-center justify-between pt-2">
        {backButton}
        <button
          onClick={submit}
          disabled={!valid || submitting}
          className="text-xs font-mono px-4 py-2 rounded bg-primary text-black hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed font-bold tracking-wider flex items-center gap-2"
        >
          {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
          I CONSENT
        </button>
      </div>
    </div>
  );
}

// ---------- STEP 5 — INSTALL ----------

function StepInstall({ onDone }: { onDone: () => void }) {
  const [progress, setProgress] = useState<Record<string, InstallProgress>>(
    {}
  );
  const [running, setRunning] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    let alive = true;

    (async () => {
      try {
        // Pull recommendations from /api/onboard/state, then start installs.
        const state = await getOnboardState();
        if (!alive) return;
        const bins = state.detected.recommendations || [];
        if (bins.length === 0) {
          setRunning(false);
          return;
        }
        // Initialize local progress map with "queued" entries so the UI shows them.
        const seed: Record<string, InstallProgress> = {};
        for (const b of bins) {
          seed[b] = {
            binary: b,
            install_id: null,
            status: 'queued',
            log: [],
          };
        }
        setProgress(seed);

        const resp = await onboardInstall(bins);
        if (!alive) return;
        // Merge install_ids from server response.
        const next: Record<string, InstallProgress> = { ...seed };
        for (const entry of resp.installs as OnboardInstallEntry[]) {
          const cur = next[entry.binary] || {
            binary: entry.binary,
            install_id: null,
            status: 'queued' as const,
            log: [],
          };
          cur.install_id = entry.install_id;
          if (entry.status === 'skipped') {
            cur.status = 'skipped';
            cur.reason = entry.reason;
          } else if (entry.install_id) {
            cur.status = 'running';
          }
          next[entry.binary] = cur;
        }
        setProgress(next);

        // Open a WS per install_id and stream log lines.
        const tasks: Promise<void>[] = [];
        for (const b of bins) {
          const cur = next[b];
          if (!cur?.install_id) continue;
          // Per-binary log buffer — each stream call appends to its own copy.
          const logBuffer: string[] = [];
          tasks.push(
            streamInstall(
              cur.install_id,
              (line) => {
                logBuffer.push(line);
                if (!alive) return;
                setProgress((prev) => {
                  const prevEntry = prev[b];
                  if (!prevEntry) return prev;
                  return { ...prev, [b]: { ...prevEntry, log: [...logBuffer] } };
                });
              },
              (delta) => {
                if (!alive) return;
                setProgress((prev) => {
                  const prevEntry = prev[b];
                  if (!prevEntry) return prev;
                  return { ...prev, [b]: { ...prevEntry, ...delta } };
                });
              }
            )
          );
        }
        await Promise.allSettled(tasks);
        if (!alive) return;
        setRunning(false);
      } catch (e) {
        if (!alive) return;
        setError(String(e));
        setRunning(false);
      }
    })();

    return () => {
      alive = false;
    };
  }, []);

  const entries = Object.values(progress);
  const allDone = entries.every(
    (e) =>
      e.status === 'ok' ||
      e.status === 'failed' ||
      e.status === 'skipped'
  );

  return (
    <div className="space-y-3">
      <h2 className="text-lg font-bold text-white tracking-wide">
        Installing your toolkit
      </h2>

      {error && (
        <div className="text-destructive text-xs font-mono">{error}</div>
      )}

      {entries.length === 0 && running && (
        <div className="text-xs text-gray-400 font-mono">
          No missing tools detected. Nothing to install.
        </div>
      )}

      <div className="space-y-2">
        {entries.map((e) => (
          <InstallRow key={e.binary} entry={e} />
        ))}
      </div>

      <div className="flex items-center justify-end pt-2">
        <button
          onClick={onDone}
          disabled={running || !allDone}
          className="text-xs font-mono px-4 py-2 rounded bg-primary text-black hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed font-bold tracking-wider"
        >
          {running ? 'INSTALLING…' : 'FINISH'}
        </button>
      </div>
    </div>
  );
}

function InstallRow({ entry }: { entry: InstallProgress }) {
  const [expanded, setExpanded] = useState(false);
  const statusColor =
    entry.status === 'ok'
      ? 'text-primary'
      : entry.status === 'failed'
        ? 'text-destructive'
        : entry.status === 'skipped'
          ? 'text-yellow-500'
          : 'text-gray-400';
  const statusLabel =
    entry.status === 'running' && entry.log.length === 0
      ? 'queued'
      : entry.status;
  return (
    <div className="border border-border rounded bg-surface/40">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-3 py-2 text-[11px] font-mono"
      >
        <span className="flex items-center gap-3">
          <span className="text-gray-200 font-bold">{entry.binary}</span>
          <span className={`uppercase ${statusColor}`}>
            {statusLabel}
            {entry.exit_code !== undefined && entry.exit_code !== 0
              ? ` (exit ${entry.exit_code})`
              : ''}
          </span>
        </span>
        <span className="text-gray-500 text-[10px]">
          {expanded ? '▾' : '▸'}{' '}
          {entry.log.length > 0 ? `${entry.log.length} lines` : ''}
        </span>
      </button>
      {expanded && (
        <div className="border-t border-border bg-black/40 px-3 py-2 max-h-48 overflow-y-auto">
          {entry.reason && (
            <div className="text-[11px] text-yellow-500 font-mono mb-1">
              {entry.reason}
            </div>
          )}
          {entry.log.length === 0 ? (
            <div className="text-[11px] text-gray-600 font-mono">
              waiting for output…
            </div>
          ) : (
            <pre className="text-[11px] font-mono text-gray-300 whitespace-pre-wrap">
              {entry.log.slice(-200).join('\n')}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

function streamInstall(
  installId: string,
  onAppendLog: (line: string) => void,
  onPatch: (delta: Partial<InstallProgress>) => void
): Promise<void> {
  return new Promise((resolve) => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${window.location.host}/ws/install/${installId}`;
    let ws: WebSocket | null = null;
    try {
      ws = new WebSocket(url);
    } catch {
      resolve();
      return;
    }
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      try {
        ws?.close();
      } catch {
        /* ignore */
      }
      resolve();
    };
    // Safety timeout: 5 minutes per install, just in case.
    const safety = setTimeout(finish, 5 * 60 * 1000);

    ws.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as {
          kind: string;
          line?: string;
          status?: string;
          exit_code?: number;
          message?: string;
        };
        if (ev.kind === 'log' && typeof ev.line === 'string') {
          onPatch({ status: 'running' });
          onAppendLog(ev.line);
        } else if (ev.kind === 'done') {
          onPatch({
            status: ev.status === 'ok' ? 'ok' : 'failed',
            exit_code: ev.exit_code,
          });
          clearTimeout(safety);
          finish();
        } else if (ev.kind === 'error') {
          onPatch({
            status: 'failed',
            reason: ev.message || 'ws error',
          });
          clearTimeout(safety);
          finish();
        }
      } catch {
        /* ignore */
      }
    };
    ws.onerror = () => {
      onPatch({ status: 'failed', reason: 'ws connection error' });
      clearTimeout(safety);
      finish();
    };
    ws.onclose = () => {
      clearTimeout(safety);
      finish();
    };
  });
}

// ---------- STEP 6 — DONE ----------

function StepDone({ onFinish }: { onFinish: () => void }) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const finish = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await onboardFinish();
      setSubmitting(false);
      onFinish();
    } catch (e) {
      setError(String(e));
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold text-primary tracking-wide">
        All set!
      </h2>
      <p className="text-sm text-gray-300 leading-relaxed">
        Your environment is ready. Click FINISH to enter the dashboard.
      </p>
      {error && (
        <div className="text-destructive text-xs font-mono">{error}</div>
      )}
      <div className="flex items-center justify-end pt-2">
        <button
          onClick={finish}
          disabled={submitting}
          className="text-xs font-mono px-4 py-2 rounded bg-primary text-black hover:opacity-90 disabled:opacity-40 font-bold tracking-wider flex items-center gap-2"
        >
          {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
          FINISH
        </button>
      </div>
    </div>
  );
}

// ---------- first-run flag hook (unchanged shape, bumped key) ----------

export function useOnboardFlag(): [
  boolean,
  () => void,
  (next: boolean) => void,
] {
  const [open, setOpen] = useState(false);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    try {
      const v = localStorage.getItem(STORAGE_KEY);
      // First-run: flag absent → modal opens automatically.
      if (!v) setOpen(true);
    } catch {
      /* ignore */
    } finally {
      setHydrated(true);
    }
  }, []);

  const reopen = () => setOpen(true);
  return [hydrated ? open : false, reopen, setOpen];
}