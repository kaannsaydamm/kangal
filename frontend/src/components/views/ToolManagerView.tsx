// ToolManagerView — registry browser with install buttons.
//
// Lists all 100+ tools from /api/toolbox/tools with category/tier filters,
// a free-text search input, and a per-tool INSTALL button that streams
// install progress via /ws/install/{id}.

import { useEffect, useRef, useState } from 'react';
import { Search, Download, Loader2, Check, Box } from 'lucide-react';

import {
  api,
  getSystemDiag,
  startInstall,
  type Tool,
  type ToolCategory,
  type SystemDiag,
} from '@/lib/api';
import { InstallStream } from '@/lib/installStream';

const CATEGORY_META: Record<string, { label: string; color: string }> = {
  recon: { label: 'RECON', color: 'text-cyan-400' },
  fingerprint: { label: 'FINGERPRINT', color: 'text-blue-400' },
  vuln_scan: { label: 'VULN SCAN', color: 'text-yellow-400' },
  exploit: { label: 'EXPLOIT', color: 'text-red-500' },
  cms_scan: { label: 'CMS', color: 'text-orange-400' },
  fuzz: { label: 'FUZZ', color: 'text-purple-400' },
  api_discovery: { label: 'API', color: 'text-purple-400' },
  online_brute: { label: 'BRUTE', color: 'text-red-500' },
  offline_crack: { label: 'CRACK', color: 'text-red-500' },
  ad_exploit: { label: 'AD EXPLOIT', color: 'text-red-500' },
  ad_recon: { label: 'AD RECON', color: 'text-cyan-400' },
  ad_enum: { label: 'AD ENUM', color: 'text-blue-400' },
  mitm: { label: 'MITM', color: 'text-red-500' },
  pivoting: { label: 'PIVOT', color: 'text-purple-400' },
  post_exploit: { label: 'POST-EXPLOIT', color: 'text-red-500' },
  osint: { label: 'OSINT', color: 'text-cyan-400' },
  secret_scan: { label: 'SECRETS', color: 'text-yellow-400' },
  sast: { label: 'SAST', color: 'text-blue-400' },
  cloud_audit: { label: 'CLOUD', color: 'text-blue-400' },
  k8s_recon: { label: 'K8S', color: 'text-cyan-400' },
  waf_detect: { label: 'WAF', color: 'text-blue-400' },
  wordlist_gen: { label: 'WORDLIST', color: 'text-gray-400' },
  smtp_test: { label: 'SMTP', color: 'text-yellow-400' },
};

interface InstallProgress {
  binary: string;
  install_id: string | null;
  status: 'idle' | 'queued' | 'running' | 'ok' | 'failed' | 'error';
  log: string[];
}

export function ToolManagerView() {
  const [tools, setTools] = useState<Tool[]>([]);
  const [categories, setCategories] = useState<ToolCategory[]>([]);
  const [diag, setDiag] = useState<SystemDiag | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [activeCat, setActiveCat] = useState<string>('');
  const [tier, setTier] = useState<1 | 2 | null>(null);
  const [search, setSearch] = useState('');
  const [progress, setProgress] = useState<Record<string, InstallProgress>>({});
  const streamRef = useRef<InstallStream | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [t, c, d] = await Promise.all([
          api.toolboxTools({}),
          api.toolboxCategories(),
          getSystemDiag().catch(() => null),
        ]);
        if (!alive) return;
        setTools(t.tools);
        setCategories(c.categories);
        if (d) setDiag(d);
      } catch (e) {
        if (alive) setErr(String(e));
      }
    })();
    return () => {
      alive = false;
      streamRef.current?.close();
    };
  }, []);

  const filtered = tools.filter((t) => {
    if (activeCat && t.category !== activeCat) return false;
    if (tier !== null && t.tier !== tier) return false;
    if (search) {
      const q = search.toLowerCase();
      if (
        !t.name.toLowerCase().includes(q) &&
        !t.binary.toLowerCase().includes(q) &&
        !t.category.toLowerCase().includes(q)
      ) {
        return false;
      }
    }
    return true;
  });

  const isInstalled = (tool: Tool): boolean => {
    if (!diag) return false;
    const probe = diag.binaries[tool.binary] || diag.binaries[tool.name];
    return !!probe?.present;
  };

  const missingRecommended = filtered.filter((t) => !isInstalled(t) && t.tier === 1);

  const onInstall = async (tool: Tool) => {
    const binary = diag?.binaries[tool.binary] ? tool.binary : tool.name;
    setProgress((prev) => ({
      ...prev,
      [binary]: { binary, install_id: null, status: 'queued', log: [] },
    }));
    let installId: string;
    try {
      const r = await startInstall(binary);
      installId = r.install_id;
      setProgress((prev) => ({
        ...prev,
        [binary]: {
          binary,
          install_id: installId,
          status: 'running',
          log: [`$ ${r.command_str}`],
        },
      }));
    } catch (e) {
      setProgress((prev) => ({
        ...prev,
        [binary]: { binary, install_id: null, status: 'error', log: [String(e)] },
      }));
      return;
    }

    streamRef.current?.close();
    const stream = new InstallStream(installId);
    streamRef.current = stream;

    stream.addEventListener('log', (ev) => {
      const e = ev as CustomEvent<{ line: string }>;
      setProgress((prev) => {
        const cur = prev[binary];
        if (!cur) return prev;
        return { ...prev, [binary]: { ...cur, log: [...cur.log, e.detail.line] } };
      });
    });
    stream.addEventListener('done', (ev) => {
      const e = ev as CustomEvent<{ status: 'ok' | 'failed' }>;
      setProgress((prev) => {
        const cur = prev[binary];
        if (!cur) return prev;
        return { ...prev, [binary]: { ...cur, status: e.detail.status } };
      });
    });
    stream.addEventListener('error', (ev) => {
      const e = ev as CustomEvent<{ message: string }>;
      setProgress((prev) => {
        const cur = prev[binary];
        if (!cur) return prev;
        return { ...prev, [binary]: { ...cur, status: 'error', log: [...cur.log, e.detail.message] } };
      });
    });

    stream.connect();
  };

  const installAllMissing = async () => {
    for (const t of missingRecommended) {
      // sequential so we don't trigger the installer's concurrency cap
      // eslint-disable-next-line no-await-in-loop
      await onInstall(t);
    }
  };

  return (
    <div className="flex flex-col h-full min-h-0 p-3 gap-3">
      {/* Header */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Box className="w-4 h-4 text-primary" />
          <span className="text-sm font-mono text-white tracking-widest uppercase">
            Tool Manager
          </span>
          <span className="text-[10px] font-mono text-gray-500">
            {filtered.length}/{tools.length} tools
          </span>
        </div>
        <button
          onClick={installAllMissing}
          disabled={missingRecommended.length === 0}
          className="text-[10px] font-mono px-2 py-1 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-1"
        >
          <Download className="w-3 h-3" />
          INSTALL {missingRecommended.length} MISSING T1
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-1.5 flex-wrap">
        <div className="flex items-center gap-1 bg-surface border border-border rounded px-2 py-1">
          <Search className="w-3 h-3 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="search…"
            className="bg-transparent outline-none text-[11px] font-mono text-gray-200 placeholder:text-gray-600 w-32"
          />
        </div>
        <button
          onClick={() => setTier(null)}
          className={`text-[10px] font-mono px-2 py-1 rounded ${
            tier === null ? 'bg-primary text-primary-foreground' : 'bg-surface text-gray-400 border border-border'
          }`}
        >
          ALL
        </button>
        <button
          onClick={() => setTier(1)}
          className={`text-[10px] font-mono px-2 py-1 rounded ${
            tier === 1 ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'bg-surface text-gray-400 border border-border'
          }`}
        >
          TIER 1
        </button>
        <button
          onClick={() => setTier(2)}
          className={`text-[10px] font-mono px-2 py-1 rounded ${
            tier === 2 ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'bg-surface text-gray-400 border border-border'
          }`}
        >
          TIER 2
        </button>
        <select
          value={activeCat}
          onChange={(e) => setActiveCat(e.target.value)}
          className="text-[10px] font-mono bg-surface border border-border text-gray-300 rounded px-1 py-1 ml-auto"
        >
          <option value="">all categories ({categories.length})</option>
          {categories.map((c) => (
            <option key={c.category} value={c.category}>
              {c.category} ({c.tools})
            </option>
          ))}
        </select>
      </div>

      {err && <div className="text-[10px] font-mono text-destructive">ERR: {err}</div>}

      {/* Tool list */}
      <div className="flex-1 min-h-0 overflow-y-auto space-y-1 pr-1">
        {filtered.map((t) => {
          const meta = CATEGORY_META[t.category] || { label: t.category.toUpperCase(), color: 'text-gray-400' };
          const installed = isInstalled(t);
          const prog = progress[t.binary] || progress[t.name];
          const status = prog?.status || 'idle';
          return (
            <div
              key={t.name}
              className={`px-2 py-1.5 border rounded ${
                installed
                  ? 'border-border bg-surface/40'
                  : 'border-destructive/30 bg-destructive/5'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span
                    className={`text-[9px] font-mono px-1 rounded ${
                      t.tier === 1
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                    }`}
                  >
                    T{t.tier}
                  </span>
                  <span className="text-xs font-mono text-gray-200 truncate" title={t.name}>
                    {t.name}
                  </span>
                  <span className={`text-[9px] font-mono ${meta.color}`}>· {meta.label}</span>
                  {installed && <Check className="w-3 h-3 text-primary" />}
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  {status === 'running' || status === 'queued' ? (
                    <span className="text-[10px] text-yellow-400 font-bold flex items-center gap-1">
                      <Loader2 className="w-3 h-3 animate-spin" />
                    </span>
                  ) : status === 'ok' ? (
                    <span className="text-[10px] text-primary font-bold">DONE</span>
                  ) : status === 'failed' || status === 'error' ? (
                    <span className="text-[10px] text-destructive font-bold">FAIL</span>
                  ) : installed ? (
                    <span className="text-[10px] text-gray-500 font-bold">—</span>
                  ) : (
                    <button
                      onClick={() => onInstall(t)}
                      className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 flex items-center gap-1"
                    >
                      <Download className="w-3 h-3" /> INSTALL
                    </button>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 text-[9px] font-mono text-gray-500 mt-0.5 truncate">
                <span className="truncate">cmd: {t.binary}</span>
                <span>·</span>
                <span>fmt: {t.output_format}</span>
                <span>·</span>
                <span>{t.timeout_default_s}s</span>
                {t.requires_root && (
                  <>
                    <span>·</span>
                    <span className="text-red-400">root</span>
                  </>
                )}
              </div>
              {prog && prog.log.length > 0 && (
                <pre className="mt-1 text-[9px] font-mono text-gray-500 max-h-16 overflow-y-auto bg-black/40 rounded p-1 whitespace-pre-wrap break-all">
                  {prog.log.slice(-6).join('\n')}
                </pre>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && !err && (
          <div className="text-[10px] font-mono text-gray-500 px-2 py-1 text-center">
            no tools match filter
          </div>
        )}
      </div>
    </div>
  );
}
