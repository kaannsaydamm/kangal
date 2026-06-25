import { useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import 'xterm/css/xterm.css';

interface XTermTerminalProps {
  logs: string[];
  title?: string;
  className?: string;
}

export function XTermTerminal({ logs, title = "Live Terminal", className }: XTermTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  useEffect(() => {
    if (!terminalRef.current) return;

    // Initialize xterm.js
    const term = new Terminal({
      theme: {
        background: '#121212',
        foreground: '#00ff41',
        cursor: '#00ff41',
        black: '#000000',
        red: '#ef4444',
        green: '#00ff41',
        yellow: '#facc15',
        blue: '#3b82f6',
        magenta: '#d946ef',
        cyan: '#06b6d4',
        white: '#ffffff',
      },
      fontFamily: '"Fira Code", monospace',
      fontSize: 13,
      cursorBlink: true,
      disableStdin: true,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(new WebLinksAddon());

    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    const handleResize = () => {
      fitAddon.fit();
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      term.dispose();
    };
  }, []);

  // Update logs
  useEffect(() => {
    if (xtermRef.current) {
      // Clear and re-write for simplicity in this demo, or append diffs
      xtermRef.current.clear();
      logs.forEach(log => xtermRef.current?.writeln(log));
    }
  }, [logs]);

  return (
    <div className={`flex flex-col h-full border border-border rounded-lg overflow-hidden bg-surface shadow ${className || ''}`}>
      <div className="bg-background border-b border-border px-4 py-2 flex items-center justify-between">
        <span className="text-xs font-mono text-gray-400">{title}</span>
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
        </div>
      </div>
      <div className="flex-1 p-2" ref={terminalRef} style={{ overflow: 'hidden' }} />
    </div>
  );
}
