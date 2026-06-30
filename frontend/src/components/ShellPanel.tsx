import { useEffect, useRef, useState } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import 'xterm/css/xterm.css';
import { BiStream } from '@/lib/biStream';
import { api } from '@/lib/api';

interface ShellPanelProps {
  /** Optional override: if provided, the panel binds to this existing session
   *  instead of asking the backend to spawn a fresh one. */
  sessionId?: string;
  onClose?: () => void;
  className?: string;
}

type Status = 'idle' | 'connecting' | 'open' | 'exit' | 'error';

export function ShellPanel({ sessionId, onClose, className }: ShellPanelProps) {
  const termRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const streamRef = useRef<BiStream | null>(null);
  const sessionIdRef = useRef<string | null>(sessionId ?? null);

  const [status, setStatus] = useState<Status>('idle');
  const [errMsg, setErrMsg] = useState<string | null>(null);

  // -------- spawn a session if we don't have one yet --------
  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      if (sessionIdRef.current) return; // already provided
      try {
        setStatus('connecting');
        // Conservative defaults — actual size sent after FitAddon.fit().
        const sess = await api.createShellSession(120, 32);
        if (cancelled) {
          api.deleteShellSession(sess.session_id).catch(() => {});
          return;
        }
        sessionIdRef.current = sess.session_id;
        attachStream(sess.session_id);
      } catch (e: unknown) {
        if (cancelled) return;
        setStatus('error');
        setErrMsg(e instanceof Error ? e.message : String(e));
      }
    };
    init();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // -------- mount xterm (once) --------
  useEffect(() => {
    const host = termRef.current;
    if (!host) return;

    // StrictMode double-mount guard
    const existing = (host as unknown as { __xterm__?: { dispose: () => void } }).__xterm__;
    if (existing) {
      try {
        existing.dispose();
      } catch {
        // ignore
      }
      (host as unknown as { __xterm__?: unknown }).__xterm__ = undefined;
    }

    const term = new Terminal({
      theme: {
        background: '#0a0a0a',
        foreground: '#00ff41',
        cursor: '#00ff41',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#facc15',
        blue: '#3b82f6',
        magenta: '#d946ef',
        cyan: '#06b6d4',
        white: '#e5e5e5',
      },
      fontFamily: '"Fira Code", monospace',
      fontSize: 12,
      cursorBlink: true,
      convertEol: true,
      // CRITICAL: stdin is enabled — the operator types into the bash.
      disableStdin: false,
      // Allow wide xterm escape sequences (e.g. ripgrep alt-screen)
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    xtermRef.current = term;
    fitRef.current = fit;
    (host as unknown as { __xterm__?: { dispose: () => void } }).__xterm__ = term;

    // Open xterm immediately (unconditional) so the .xterm class always
    // exists in the DOM the moment the panel mounts — required for
    // Playwright/scroll-mount detection. Resize/fit is gated on real
    // dimensions coming from requestAnimationFrame / ResizeObserver.
    if (!host.querySelector('.xterm')) {
      try {
        term.open(host);
      } catch (e) {
        // First open might race the layout commit. Inject a sized
        // placeholder so xterm has real dimensions, then open.
        const placeholder = document.createElement('div');
        placeholder.style.width = '100%';
        placeholder.style.height = '100%';
        host.appendChild(placeholder);
        try {
          term.open(placeholder);
        } catch (e2) {
          console.warn('xterm open failed:', e2);
        }
      }
    }

    // Forward xterm keystrokes to the PTY.
    term.onData((d) => {
      streamRef.current?.writeBytes(new TextEncoder().encode(d));
    });
    // Forward xterm resize to the PTY.
    term.onResize(({ cols, rows }) => {
      streamRef.current?.resize(cols, rows);
    });

    // Defer first fit until host has real dimensions.
    let raf2 = 0;
    let raf3 = 0;
    const fitIfSized = () => {
      const r = host.getBoundingClientRect();
      if (r.width < 40 || r.height < 40) return false;
      try {
        fit.fit();
        // Re-fit again one frame later to catch font-metric settle.
        setTimeout(() => {
          try {
            fit.fit();
            streamRef.current?.resize(
              term.cols,
              term.rows,
            );
          } catch {
            // ignore
          }
        }, 30);
        term.focus();
        return true;
      } catch (e) {
        console.warn('xterm fit failed:', e);
        return false;
      }
    };
    const raf1 = requestAnimationFrame(() => {
      raf2 = requestAnimationFrame(() => {
        if (fitIfSized()) return;
        raf3 = requestAnimationFrame(() => fitIfSized());
      });
    });

    const ro = new ResizeObserver(() => {
      try {
        const r = host.getBoundingClientRect();
        if (r.width < 20 || r.height < 20) return;
        fit.fit();
        streamRef.current?.resize(term.cols, term.rows);
      } catch {
        // ignore
      }
    });
    ro.observe(host);

    return () => {
      cancelAnimationFrame(raf1);
      cancelAnimationFrame(raf2);
      cancelAnimationFrame(raf3);
      ro.disconnect();
      try {
        term.dispose();
      } catch {
        // ignore
      }
      (host as unknown as { __xterm__?: unknown }).__xterm__ = undefined;
    };
  }, []);

  // -------- wire the BiStream --------
  function attachStream(sid: string) {
    if (!xtermRef.current) {
      // xterm not mounted yet — try again on next tick
      setTimeout(() => attachStream(sid), 50);
      return;
    }
    const term = xtermRef.current;
    const stream = new BiStream(sid);
    streamRef.current = stream;
    const onFrame = (f: import('@/lib/biStream').ServerFrame) => {
      if (f.kind === 'open') {
        setStatus('open');
        term.writeln('\x1b[32m[+] shell session online\x1b[0m');
      } else if (f.kind === 'out') {
        try {
          const bin = atob(f.data);
          const bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          term.write(bytes);
        } catch {
          // ignore decode errors
        }
      } else if (f.kind === 'exit') {
        setStatus('exit');
        term.writeln(`\r\n\x1b[33m[!] bash exited (code=${f.code})\x1b[0m`);
      } else if (f.kind === 'error') {
        setStatus('error');
        setErrMsg(f.message);
        term.writeln(`\r\n\x1b[31m[!] shell error: ${f.message}\x1b[0m`);
      }
    };
    stream.on(onFrame);
    stream.connect();
  }

  // -------- teardown --------
  const kill = async () => {
    const sid = sessionIdRef.current;
    if (streamRef.current) {
      streamRef.current.close();
      streamRef.current = null;
    }
    if (sid) {
      try {
        await api.deleteShellSession(sid);
      } catch {
        // ignore — reaper will collect it
      }
    }
    onClose?.();
  };

  const statusColor =
    status === 'open'
      ? 'bg-green-500'
      : status === 'exit'
        ? 'bg-yellow-500'
        : status === 'error'
          ? 'bg-red-500'
          : 'bg-blue-500';

  return (
    <div
      className={`flex flex-col h-full border border-border rounded-lg overflow-hidden bg-background shadow ${className || ''}`}
    >
      <div className="bg-surface border-b border-border px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-gray-400">
            Interactive Shell
          </span>
          <span className={`w-2 h-2 rounded-full ${statusColor}`} title={status} />
          <span className="text-[10px] font-mono text-gray-500 uppercase">
            {status}
          </span>
          {errMsg && (
            <span className="text-[10px] font-mono text-red-400 truncate max-w-[280px]">
              {errMsg}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {onClose && (
            <button
              onClick={onClose}
              className="text-[10px] font-mono px-2 py-1 rounded bg-surface text-gray-400 border border-border hover:bg-surface/60"
              title="Hide shell (bash keeps running)"
            >
              HIDE
            </button>
          )}
          <button
            onClick={kill}
            className="text-[10px] font-mono px-2 py-1 rounded bg-red-700/40 text-red-200 border border-red-700 hover:bg-red-700/60"
            title="Kill the bash process"
          >
            KILL
          </button>
          <div className="flex gap-1.5 ml-1">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
            <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
          </div>
        </div>
      </div>
      <div
        ref={termRef}
        className="flex-1 min-h-[200px] relative"
        style={{ overflow: 'hidden', minHeight: '200px' }}
      />
    </div>
  );
}
