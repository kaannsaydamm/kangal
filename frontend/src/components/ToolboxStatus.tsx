import { useEffect, useState } from 'react';
import { Box, AlertTriangle, Shield, Skull, Crosshair } from 'lucide-react';
import { api, type Tool } from '@/lib/api';

interface ToolboxStatusProps {
  compact?: boolean;
}

const CATEGORY_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  recon: { label: 'RECON', icon: <Crosshair className="w-3 h-3" />, color: 'text-cyan-400' },
  fingerprint: { label: 'FINGERPRINT', icon: <Shield className="w-3 h-3" />, color: 'text-blue-400' },
  vuln_scan: { label: 'VULN SCAN', icon: <AlertTriangle className="w-3 h-3" />, color: 'text-yellow-400' },
  exploit: { label: 'EXPLOIT', icon: <Skull className="w-3 h-3" />, color: 'text-red-500' },
  cms_scan: { label: 'CMS', icon: <Box className="w-3 h-3" />, color: 'text-orange-400' },
  fuzz: { label: 'FUZZ', icon: <Box className="w-3 h-3" />, color: 'text-purple-400' },
  api_discovery: { label: 'API', icon: <Box className="w-3 h-3" />, color: 'text-purple-400' },
  online_brute: { label: 'BRUTE', icon: <Skull className="w-3 h-3" />, color: 'text-red-500' },
  offline_crack: { label: 'CRACK', icon: <Skull className="w-3 h-3" />, color: 'text-red-500' },
  ad_exploit: { label: 'AD EXPLOIT', icon: <Skull className="w-3 h-3" />, color: 'text-red-500' },
  ad_recon: { label: 'AD RECON', icon: <Crosshair className="w-3 h-3" />, color: 'text-cyan-400' },
  ad_enum: { label: 'AD ENUM', icon: <Box className="w-3 h-3" />, color: 'text-blue-400' },
  mitm: { label: 'MITM', icon: <Skull className="w-3 h-3" />, color: 'text-red-500' },
  pivoting: { label: 'PIVOT', icon: <Box className="w-3 h-3" />, color: 'text-purple-400' },
  post_exploit: { label: 'POST-EXPLOIT', icon: <Skull className="w-3 h-3" />, color: 'text-red-500' },
  osint: { label: 'OSINT', icon: <Box className="w-3 h-3" />, color: 'text-cyan-400' },
  secret_scan: { label: 'SECRETS', icon: <AlertTriangle className="w-3 h-3" />, color: 'text-yellow-400' },
  sast: { label: 'SAST', icon: <Shield className="w-3 h-3" />, color: 'text-blue-400' },
  cloud_audit: { label: 'CLOUD', icon: <Box className="w-3 h-3" />, color: 'text-blue-400' },
  k8s_recon: { label: 'K8S', icon: <Box className="w-3 h-3" />, color: 'text-cyan-400' },
  waf_detect: { label: 'WAF', icon: <Shield className="w-3 h-3" />, color: 'text-blue-400' },
  wordlist_gen: { label: 'WORDLIST', icon: <Box className="w-3 h-3" />, color: 'text-gray-400' },
  smtp_test: { label: 'SMTP', icon: <Box className="w-3 h-3" />, color: 'text-yellow-400' },
};

export function ToolboxStatus({ compact = false }: ToolboxStatusProps) {
  const [summary, setSummary] = useState<{ total: number; by_tier: Record<string, number>; by_category: Record<string, number>; registry_path: string | null } | null>(null);
  const [categories, setCategories] = useState<{ category: string; tools: number; tiers: number[] }[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [s, c] = await Promise.all([api.toolboxSummary(), api.toolboxCategories()]);
        if (!alive) return;
        setSummary(s);
        setCategories(c.categories);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const t = setInterval(load, 15000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  if (err) {
    return (
      <div className="text-[10px] font-mono text-yellow-500 px-2 py-1">
        TOOLBOX: {err.slice(0, 50)}
      </div>
    );
  }
  if (!summary) {
    return (
      <div className="text-[10px] font-mono text-gray-500 px-2 py-1">
        TOOLBOX: connecting…
      </div>
    );
  }

  if (compact) {
    return (
      <div className="flex items-center gap-1.5 text-[10px] font-mono" title="Toolbox registry">
        <Box className="w-3 h-3 text-primary" />
        <span className="text-primary font-bold">{summary.total}</span>
        <span className="text-gray-500">TOOLS</span>
        <span className="text-gray-600">·</span>
        <span className="text-cyan-400">T1: {summary.by_tier['1'] || 0}</span>
        <span className="text-gray-600">·</span>
        <span className="text-purple-400">T2: {summary.by_tier['2'] || 0}</span>
      </div>
    );
  }

  return (
    <div className="border border-border rounded-lg bg-surface/40 p-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono text-gray-400 uppercase flex items-center gap-1.5">
          <Box className="w-3.5 h-3.5 text-primary" />
          Toolbox
        </div>
        <div className="text-[10px] font-mono text-gray-500">
          T1: {summary.by_tier['1'] || 0} · T2: {summary.by_tier['2'] || 0}
        </div>
      </div>
      <div className="grid grid-cols-2 gap-1.5">
        {categories.map((c) => {
          const meta = CATEGORY_META[c.category] || { label: c.category.toUpperCase(), icon: <Box className="w-3 h-3" />, color: 'text-gray-400' };
          return (
            <div
              key={c.category}
              className="flex items-center justify-between px-2 py-1 bg-surface/60 border border-border rounded text-[10px] font-mono"
            >
              <span className={`flex items-center gap-1 ${meta.color}`}>
                {meta.icon}
                {meta.label}
              </span>
              <span className="text-gray-300 font-bold">{c.tools}</span>
            </div>
          );
        })}
      </div>
      {summary.registry_path && (
        <div className="text-[9px] font-mono text-gray-600 truncate" title={summary.registry_path}>
          reg: {summary.registry_path.split('/').pop()}
        </div>
      )}
    </div>
  );
}

interface ToolInventoryProps {
  onPickTool?: (tool: Tool) => void;
}

export function ToolInventory({ onPickTool }: ToolInventoryProps) {
  const [tools, setTools] = useState<Tool[]>([]);
  const [categories, setCategories] = useState<{ category: string; tools: number; tiers: number[] }[]>([]);
  const [activeCat, setActiveCat] = useState<string | null>(null);
  const [tier, setTier] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [c, t] = await Promise.all([api.toolboxCategories(), api.toolboxTools({})]);
        if (!alive) return;
        setCategories(c.categories);
        setTools(t.tools);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const filtered = tools.filter((t) => {
    if (activeCat && t.category !== activeCat) return false;
    if (tier && t.tier !== tier) return false;
    return true;
  });

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-1.5 mb-2">
        <Box className="w-3.5 h-3.5 text-primary" />
        <span className="text-xs font-mono text-gray-300 uppercase">Tool Inventory</span>
        <span className="text-[10px] font-mono text-gray-500">({filtered.length})</span>
      </div>

      <div className="flex items-center gap-1 mb-2 flex-wrap">
        <button
          onClick={() => setTier(null)}
          className={`text-[10px] font-mono px-2 py-0.5 rounded ${
            tier === null ? 'bg-primary text-primary-foreground' : 'bg-surface text-gray-400 border border-border'
          }`}
        >
          ALL
        </button>
        <button
          onClick={() => setTier(1)}
          className={`text-[10px] font-mono px-2 py-0.5 rounded ${
            tier === 1 ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'bg-surface text-gray-400 border border-border'
          }`}
        >
          TIER 1
        </button>
        <button
          onClick={() => setTier(2)}
          className={`text-[10px] font-mono px-2 py-0.5 rounded ${
            tier === 2 ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40' : 'bg-surface text-gray-400 border border-border'
          }`}
        >
          TIER 2
        </button>
        <select
          value={activeCat || ''}
          onChange={(e) => setActiveCat(e.target.value || null)}
          className="text-[10px] font-mono bg-surface border border-border text-gray-300 rounded px-1 py-0.5 ml-auto"
        >
          <option value="">all categories</option>
          {categories.map((c) => (
            <option key={c.category} value={c.category}>
              {c.category} ({c.tools})
            </option>
          ))}
        </select>
      </div>

      {err && <div className="text-[10px] font-mono text-yellow-500">{err}</div>}

      <div className="flex-1 overflow-y-auto space-y-1 pr-1">
        {filtered.map((t) => {
          const meta = CATEGORY_META[t.category] || { color: 'text-gray-400' };
          return (
            <div
              key={t.name}
              onClick={() => onPickTool?.(t)}
              className="px-2 py-1.5 border border-border rounded bg-surface/40 hover:bg-surface/80 cursor-pointer"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <span
                    className={`text-[9px] font-mono px-1 rounded ${
                      t.tier === 1
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        : 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                    }`}
                  >
                    T{t.tier}
                  </span>
                  <span className="text-xs font-mono text-gray-200">{t.name}</span>
                </div>
                <span className={`text-[9px] font-mono ${meta.color}`}>{t.category}</span>
              </div>
              <div className="flex items-center gap-2 text-[9px] font-mono text-gray-500 mt-0.5">
                <span>bin: {t.binary}</span>
                <span>·</span>
                <span>fmt: {t.output_format}</span>
                <span>·</span>
                <span>timeout: {t.timeout_default_s}s</span>
                {t.requires_root && (
                  <>
                    <span>·</span>
                    <span className="text-red-400">root</span>
                  </>
                )}
                {t.rate_limit_per_min > 0 && (
                  <>
                    <span>·</span>
                    <span>rate: {t.rate_limit_per_min}/m</span>
                  </>
                )}
              </div>
            </div>
          );
        })}
        {filtered.length === 0 && !err && (
          <div className="text-[10px] font-mono text-gray-500 px-2 py-1">no tools match filter</div>
        )}
      </div>
    </div>
  );
}
