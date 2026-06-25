import { useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import 'xterm/css/xterm.css';
import type { TerminalLine } from '@/lib/store';

interface LiveTerminalProps {
  lines: TerminalLine[];
  title?: string;
  className?: string;
}

const LEVEL_COLORS: Record<string, string> = {
  info: '\x1b[36m',     // cyan
  success: '\x1b[32m',  // green
  warn: '\x1b[33m',     // yellow
  error: '\x1b[31m',    // red
};
const RESET = '\x1b[0m';

export function LiveTerminal({ lines, title = 'Live Shell', className }: LiveTerminalProps) {
  const termRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const lastCountRef = useRef(0);

  useEffect(() => {
    const host = termRef.current;
    if (!host) return;

    // Guard against React StrictMode double-mount: if the host already has
    // an xterm instance attached, dispose it first so we don't leak a renderer.
    const existing = (host as unknown as { __xterm__?: { dispose: () => void } }).__xterm__;
    if (existing) {
      try { existing.dispose(); } catch {}
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
      disableStdin: true,
      convertEol: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new WebLinksAddon());
    xtermRef.current = term;
    fitRef.current = fit;
    (host as unknown as { __xterm__?: { dispose: () => void } }).__xterm__ = term;

    // Defer BOTH `open` and the first `fit` until the host has a real size
    // AND the renderer service is ready. Calling `open()` synchronously
    // inside the effect crashes xterm's viewport because the parent's
    // box hasn't been measured yet under Vite + React 19 + StrictMode.
    let raf2 = 0;
    let raf3 = 0;
    const openAndFit = () => {
      const r = host.getBoundingClientRect();
      if (r.width < 40 || r.height < 40) return false;
      try {
        if (!host.querySelector('.xterm')) {
          term.open(host);
        }
        fit.fit();
        term.writeln('\x1b[32m[+] kangal stream online\x1b[0m');
        return true;
      } catch (e) {
        console.warn('xterm open/fit failed:', e);
        return false;
      }
    };
    const raf1 = requestAnimationFrame(() => {
      raf2 = requestAnimationFrame(() => {
        if (openAndFit()) return;
        raf3 = requestAnimationFrame(() => openAndFit());
      });
    });

    const ro = new ResizeObserver(() => {
      try {
        const r = host.getBoundingClientRect();
        if (r.width < 20 || r.height < 20) return;
        fit.fit();
      } catch {}
    });
    ro.observe(host);

    const onResize = () => {
      try {
        const r = host.getBoundingClientRect();
        if (r.width < 20 || r.height < 20) return;
        fit.fit();
      } catch {}
    };
    window.addEventListener('resize', onResize);
    return () => {
      cancelAnimationFrame(raf1);
      cancelAnimationFrame(raf2);
      cancelAnimationFrame(raf3);
      ro.disconnect();
      window.removeEventListener('resize', onResize);
      try { term.dispose(); } catch {}
      (host as unknown as { __xterm__?: unknown }).__xterm__ = undefined;
    };
  }, []);

  // Append-only writer — do NOT clear on each render
  useEffect(() => {
    const term = xtermRef.current;
    if (!term) return;
    for (let i = lastCountRef.current; i < lines.length; i++) {
      const l = lines[i];
      const color = LEVEL_COLORS[l.level] || '\x1b[37m';
      const ts = l.ts ? new Date(l.ts).toLocaleTimeString() : '';
      term.writeln(
        `${'\x1b[90m' + ts + RESET} ${color}[${l.stage.toUpperCase()}]${RESET} ${l.message}`
      );
    }
    lastCountRef.current = lines.length;
  }, [lines]);

  return (
    <div className={`flex flex-col h-full border border-border rounded-lg overflow-hidden bg-background shadow ${className || ''}`}>
      <div className="bg-surface border-b border-border px-4 py-2 flex items-center justify-between">
        <span className="text-xs font-mono text-gray-400">{title}</span>
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
        </div>
      </div>
      <div
        ref={termRef}
        className="flex-1 min-h-0 relative"
        style={{ overflow: 'hidden', minHeight: 0 }}
      />
    </div>
  );
}