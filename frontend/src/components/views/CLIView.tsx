// CLIView — kangal-cli install snippet for the detected OS.
//
// Detects platform via /api/system/diag and renders one of:
//   macOS   : brew install ... + pip install -e cli/
//   Linux   : apt install ...  + pip install -e cli/
//   Windows : pip install -e cli/
// "Copy to clipboard" button copies the multi-line block.

import { useEffect, useState } from 'react';
import { Copy, Check, Terminal as TerminalIcon, Loader2 } from 'lucide-react';

import { getSystemDiag, type SystemDiag } from '@/lib/api';

type OSType = 'macos' | 'linux' | 'windows' | 'unknown';

function detectOS(d: SystemDiag | null): OSType {
  if (!d?.host) return 'unknown';
  const sys = d.host.system.toLowerCase();
  if (sys.includes('darwin')) return 'macos';
  if (sys.includes('windows')) return 'windows';
  if (sys.includes('linux') || d.host.is_wsl) return 'linux';
  return 'unknown';
}

function buildSnippet(os: OSType): { label: string; lines: string[] } {
  switch (os) {
    case 'macos':
      return {
        label: 'macOS',
        lines: [
          '# 1. install system deps',
          'brew install python@3.12 git nmap nuclei httpx',
          '',
          '# 2. install kangal-cli (editable, from this repo)',
          'cd /path/to/kangal',
          'pip3 install -e cli/',
          '',
          '# 3. verify',
          'kangal --version',
          'kangal toolbox summary',
        ],
      };
    case 'linux':
      return {
        label: 'Linux / WSL',
        lines: [
          '# 1. install system deps',
          'sudo apt update && sudo apt install -y python3 python3-pip git nmap curl',
          '',
          '# 2. install kangal-cli (editable, from this repo)',
          'cd /path/to/kangal',
          'pip3 install -e cli/',
          '',
          '# 3. verify',
          'kangal --version',
          'kangal toolbox summary',
        ],
      };
    case 'windows':
      return {
        label: 'Windows',
        lines: [
          '# 1. install Python + git (skip if already installed)',
          'winget install Python.Python.3.12 Git.Git',
          '',
          '# 2. install kangal-cli (editable, from this repo)',
          'cd C:\\path\\to\\kangal',
          'pip install -e cli/',
          '',
          '# 3. verify',
          'kangal --version',
          'kangal toolbox summary',
        ],
      };
    default:
      return {
        label: 'Unknown',
        lines: ['# platform not detected — see README.md'],
      };
  }
}

export function CLIView() {
  const [diag, setDiag] = useState<SystemDiag | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const d = await getSystemDiag();
        if (alive) setDiag(d);
      } catch (e) {
        if (alive) setErr(String(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const os = detectOS(diag);
  const snippet = buildSnippet(os);
  const text = snippet.lines.join('\n');

  const copy = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback: temporary textarea
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setErr(String(e));
    }
  };

  return (
    <div className="flex flex-col h-full min-h-0 p-3 gap-3">
      <div className="flex items-center gap-2">
        <TerminalIcon className="w-4 h-4 text-primary" />
        <span className="text-sm font-mono text-white tracking-widest uppercase">
          Kangal CLI
        </span>
        {diag && (
          <span className="text-[10px] font-mono text-gray-500">
            detected: {snippet.label} ({diag.host.system})
          </span>
        )}
      </div>

      {loading && (
        <div className="text-[10px] font-mono text-gray-500 flex items-center gap-1">
          <Loader2 className="w-3 h-3 animate-spin" /> detecting platform…
        </div>
      )}

      {err && <div className="text-[10px] font-mono text-destructive">ERR: {err}</div>}

      <div className="text-[11px] font-mono text-gray-400">
        Run the snippet below in your terminal to install the kangal-cli tool and
        its core dependencies. After install,{' '}
        <span className="text-primary">kangal toolbox summary</span> should report
        all 100+ tools.
      </div>

      <div className="flex-1 min-h-0 border border-border rounded bg-black/60 overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-border bg-surface/40">
          <span className="text-[10px] font-mono text-gray-400">
            install snippet — {snippet.label}
          </span>
          <button
            onClick={copy}
            className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 flex items-center gap-1"
          >
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
            {copied ? 'COPIED' : 'COPY'}
          </button>
        </div>
        <pre className="text-[11px] font-mono text-gray-200 p-3 overflow-auto whitespace-pre-wrap break-all flex-1">
          {text}
        </pre>
      </div>

      <div className="text-[9px] font-mono text-gray-600 space-y-0.5">
        <div>
          kangal-cli is a thin wrapper around the same REST/WS API the dashboard
          uses. It supports <span className="text-gray-400">kangal toolbox</span>,{' '}
          <span className="text-gray-400">kangal scan</span>,{' '}
          <span className="text-gray-400">kangal intel</span>, and more — see{' '}
          <span className="text-primary">cli/README.md</span>.
        </div>
        {diag?.host && (
          <div>
            host: {diag.host.system} {diag.host.release} · arch {diag.host.machine} ·
            python {diag.host.python_version}
          </div>
        )}
      </div>
    </div>
  );
}
