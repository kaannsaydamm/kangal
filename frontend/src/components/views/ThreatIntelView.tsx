// ThreatIntelView — live CVE feed + MITRE ATT&CK technique browser.
// All fetches go through api.ts helpers with a 10s client-side timeout.

import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, ExternalLink, Loader2, RefreshCw, Search, Shield, Skull, Target,
} from 'lucide-react';
import {
  getThreatIntelFeed, getRecentCVEs, getMitreTechnique, searchMitre,
  type CVE, type MitreTechnique, type ThreatIntelFeed,
} from '@/lib/api';

type Tab = 'cves' | 'mitre';
type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
const DAY_OPTS = [1, 7, 14, 30];
const ALL_SEVS: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const TACTIC_TONE: Record<string, string> = {
  'initial-access': 'border-red-500/40 text-red-400',
  execution: 'border-orange-500/40 text-orange-400',
  persistence: 'border-yellow-500/40 text-yellow-400',
  'privilege-escalation': 'border-yellow-500/40 text-yellow-400',
  'defense-evasion': 'border-purple-500/40 text-purple-400',
  'credential-access': 'border-pink-500/40 text-pink-400',
  discovery: 'border-blue-500/40 text-blue-400',
  'lateral-movement': 'border-cyan-500/40 text-cyan-400',
  collection: 'border-teal-500/40 text-teal-400',
  'command-and-control': 'border-indigo-500/40 text-indigo-400',
  exfiltration: 'border-rose-500/40 text-rose-400',
  impact: 'border-red-600/40 text-red-500',
};
const cvssColor = (s: number | null) =>
  s == null ? 'text-gray-400' : s >= 9 ? 'text-red-500' : s >= 7 ? 'text-orange-500' : s >= 4 ? 'text-yellow-500' : 'text-gray-400';
const tacticChip = (t: string) =>
  `text-[9px] font-mono px-1 py-0.5 rounded border ${TACTIC_TONE[t] ?? 'border-border text-gray-400'}`;
const mitreUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}`;

function CveCard({ cve }: { cve: CVE }) {
  const [open, setOpen] = useState(false);
  const score = cve.cvss_v3?.score ?? null;
  const sev = (cve.cvss_v3?.severity ?? '').toUpperCase();
  return (
    <div className="border border-border rounded bg-surface/40 hover:border-primary/40 transition-colors">
      <div className="flex items-start gap-2 p-2.5">
        <Skull className={`w-4 h-4 mt-0.5 shrink-0 ${cvssColor(score)}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer"
               className="text-xs font-mono font-bold text-primary hover:underline">{cve.id}</a>
            <span className={`text-[10px] font-mono font-bold ${cvssColor(score)}`}>CVSS {score == null ? 'N/A' : score.toFixed(1)}</span>
            {sev && <span className="text-[9px] font-mono px-1 py-0.5 rounded border border-border text-gray-400">{sev}</span>}
            <span className="text-[9px] font-mono text-gray-600">{cve.published ? new Date(cve.published).toLocaleDateString() : ''}</span>
            {cve.stale && <span className="text-[9px] font-mono px-1 py-0.5 rounded border border-yellow-500/40 text-yellow-400">STALE</span>}
          </div>
          <div className="text-[11px] font-mono text-gray-300 line-clamp-2">{cve.description}</div>
        </div>
        <button onClick={() => setOpen((v) => !v)}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 shrink-0">
          {open ? 'HIDE' : 'VIEW'}
        </button>
      </div>
      {open && (
        <div className="border-t border-border px-3 py-2 bg-black/30 space-y-2">
          <div className="text-[10px] font-mono text-gray-300 whitespace-pre-wrap">{cve.description}</div>
          {cve.references.length > 0 && (
            <div className="space-y-1">
              <div className="text-[9px] font-mono text-gray-500 uppercase">References</div>
              {cve.references.slice(0, 5).map((r, i) => (
                <a key={i} href={r} target="_blank" rel="noreferrer"
                   className="flex items-center gap-1 text-[10px] font-mono text-primary hover:underline truncate">
                  <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                  <span className="truncate">{r}</span>
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CvesTab({ feed, onRefresh }: { feed: ThreatIntelFeed | null; onRefresh: () => void }) {
  const [days, setDays] = useState(7);
  const [sevs, setSevs] = useState<Set<Severity>>(new Set(['CRITICAL', 'HIGH']));
  const [cves, setCves] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setErr(null);
    const min = ALL_SEVS.find((s) => sevs.has(s)) ?? 'HIGH';
    getRecentCVEs(days, min.toLowerCase())
      .then((r) => alive && setCves(r.cves))
      .catch((e) => alive && setErr(String(e)))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [days, sevs]);
  const filtered = cves.filter((c) => sevs.has((c.cvss_v3?.severity ?? '').toUpperCase() as Severity));
  const toggle = (s: Severity) => setSevs((p) => { const n = new Set(p); n.has(s) ? n.delete(s) : n.add(s); return n; });
  return (
    <div className="flex flex-col h-full min-h-0 gap-2">
      <div className="flex items-center gap-2 flex-wrap px-1">
        <label className="text-[10px] font-mono text-gray-500">Days:</label>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}
                className="text-[10px] font-mono bg-surface text-gray-200 border border-border rounded px-1.5 py-0.5">
          {DAY_OPTS.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
        <label className="text-[10px] font-mono text-gray-500 ml-2">Severity:</label>
        {ALL_SEVS.map((s) => (
          <button key={s} onClick={() => toggle(s)}
                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${sevs.has(s) ? 'border-primary/60 bg-primary/20 text-primary' : 'border-border bg-surface text-gray-500'}`}>
            {s}
          </button>
        ))}
        <button onClick={onRefresh} disabled={loading}
                className="ml-auto text-[10px] font-mono px-2 py-0.5 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 disabled:opacity-40 flex items-center gap-1">
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} /> REFRESH
        </button>
      </div>
      {err && <div className="text-[10px] font-mono text-destructive px-1">ERR: {err}</div>}
      <div className="flex-1 min-h-0 overflow-y-auto space-y-1.5 pr-1">
        {loading && cves.length === 0 && (
          <div className="flex items-center justify-center py-6 text-[10px] font-mono text-gray-500 gap-1">
            <Loader2 className="w-3 h-3 animate-spin" /> loading CVEs…
          </div>
        )}
        {!loading && filtered.length === 0 && (
          <div className="text-[10px] font-mono text-gray-600 text-center py-6">
            No CVEs match these filters. Try widening the date range.
          </div>
        )}
        {filtered.map((c) => <CveCard key={c.id} cve={c} />)}
      </div>
    </div>
  );
}

function MitreTab({ initial }: { initial: MitreTechnique[] }) {
  const [q, setQ] = useState('');
  const [list, setList] = useState<MitreTechnique[]>(initial);
  const [sel, setSel] = useState<MitreTechnique | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!q.trim()) { setList(initial); return; }
    let alive = true;
    setLoading(true); setErr(null);
    searchMitre(q).then((r) => alive && setList(r.results)).catch((e) => alive && setErr(String(e))).finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [q, initial]);
  const grouped = useMemo(() => {
    const g: Record<string, MitreTechnique[]> = {};
    for (const t of list) for (const tac of t.tactics.length ? t.tactics : ['other']) (g[tac] ||= []).push(t);
    for (const k of Object.keys(g)) g[k].sort((a, b) => a.id.localeCompare(b.id));
    return g;
  }, [list]);
  const open = async (t: MitreTechnique) => {
    setSel(t);
    try { setSel(await getMitreTechnique(t.id)); } catch { /* keep list copy */ }
  };
  return (
    <div className="flex flex-col h-full min-h-0 gap-2">
      <div className="flex items-center gap-1.5 px-1">
        <Search className="w-3 h-3 text-gray-500" />
        <input type="text" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search MITRE techniques…"
               className="flex-1 bg-surface border border-border rounded px-2 py-1 text-[11px] font-mono text-gray-200 placeholder:text-gray-600 outline-none focus:border-primary/60" />
        {loading && <Loader2 className="w-3 h-3 animate-spin text-primary" />}
      </div>
      {err && <div className="text-[10px] font-mono text-destructive px-1">ERR: {err}</div>}
      <div className="flex-1 min-h-0 grid grid-cols-2 gap-2">
        <div className="overflow-y-auto border border-border rounded bg-surface/40 p-1.5 space-y-2">
          {Object.keys(grouped).length === 0 && (
            <div className="text-[10px] font-mono text-gray-600 text-center py-4">No techniques loaded.</div>
          )}
          {Object.entries(grouped).map(([tac, items]) => (
            <div key={tac}>
              <div className="text-[9px] font-mono text-gray-500 uppercase tracking-wider px-1 mb-1">{tac} ({items.length})</div>
              {items.map((t) => (
                <button key={t.id} onClick={() => open(t)}
                        className={`w-full text-left flex items-center gap-2 px-1.5 py-1 rounded hover:bg-primary/10 ${sel?.id === t.id ? 'bg-primary/20' : ''}`}>
                  <Target className="w-3 h-3 text-primary shrink-0" />
                  <span className="text-[11px] font-mono text-gray-200 shrink-0">{t.id}</span>
                  <span className="text-[11px] font-mono text-gray-400 truncate">{t.name}</span>
                  {t.tactics[0] && <span className={tacticChip(t.tactics[0]) + ' ml-auto shrink-0'}>{t.tactics[0].split('-')[0]}</span>}
                </button>
              ))}
            </div>
          ))}
        </div>
        <div className="overflow-y-auto border border-border rounded bg-surface/40 p-2.5">
          {sel ? (
            <div className="space-y-2">
              <div className="flex items-start gap-2">
                <Shield className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                <div className="min-w-0">
                  <div className="text-xs font-mono font-bold text-primary">{sel.id}</div>
                  <div className="text-sm text-gray-100">{sel.name}</div>
                </div>
              </div>
              {sel.tactics.length > 0 && (
                <div className="flex flex-wrap gap-1">{sel.tactics.map((t) => <span key={t} className={tacticChip(t)}>{t}</span>)}</div>
              )}
              <div className="text-[11px] font-mono text-gray-300 whitespace-pre-wrap">{sel.description}</div>
              {sel.platforms.length > 0 && (
                <div>
                  <div className="text-[9px] font-mono text-gray-500 uppercase">Platforms</div>
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {sel.platforms.map((p) => <span key={p} className="text-[9px] font-mono px-1 py-0.5 rounded border border-border text-gray-300">{p}</span>)}
                  </div>
                </div>
              )}
              {sel.mitigations.length > 0 && (
                <div>
                  <div className="text-[9px] font-mono text-gray-500 uppercase">Mitigations</div>
                  <ul className="text-[11px] font-mono text-gray-300 list-disc list-inside">{sel.mitigations.map((m, i) => <li key={i}>{m}</li>)}</ul>
                </div>
              )}
              {sel.data_sources.length > 0 && (
                <div>
                  <div className="text-[9px] font-mono text-gray-500 uppercase">Data Sources</div>
                  <div className="text-[11px] font-mono text-gray-300">{sel.data_sources.join(', ')}</div>
                </div>
              )}
              <a href={sel.url || mitreUrl(sel.id)} target="_blank" rel="noreferrer"
                 className="inline-flex items-center gap-1 text-[10px] font-mono text-primary hover:underline">
                <ExternalLink className="w-3 h-3" /> attack.mitre.org
              </a>
            </div>
          ) : (
            <div className="text-[10px] font-mono text-gray-600 text-center py-6">Select a technique to view details.</div>
          )}
        </div>
      </div>
    </div>
  );
}

export function ThreatIntelView() {
  const [feed, setFeed] = useState<ThreatIntelFeed | null>(null);
  const [tab, setTab] = useState<Tab>('cves');
  const [err, setErr] = useState<string | null>(null);
  const load = async (refresh = false) => {
    try { setFeed(await getThreatIntelFeed(refresh)); setErr(null); }
    catch (e) { setErr(String(e)); }
  };
  useEffect(() => { load(false); }, []);
  return (
    <div className="flex flex-col h-full min-h-0 p-3 gap-2">
      <div className="flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-primary" />
        <span className="text-sm font-mono text-white tracking-widest uppercase">Threat Intel</span>
        {feed && <span className="text-[10px] font-mono text-gray-500">{feed.recent_cves.length} CVE · {feed.mitre_techniques.length} MITRE</span>}
      </div>
      {feed?.stale && (
        <div className="text-[10px] font-mono px-2 py-1 rounded border border-yellow-500/40 bg-yellow-500/10 text-yellow-300">
          ⚠ Intel is stale — backend has no live network connection. Showing last cached data.
        </div>
      )}
      {err && !feed && (
        <div className="text-[10px] font-mono text-destructive px-2 py-1 rounded border border-destructive/40 bg-destructive/10">ERR: {err}</div>
      )}
      <div className="flex items-center gap-1 px-1">
        {(['cves', 'mitre'] as Tab[]).map((t) => (
          <button key={t} onClick={() => setTab(t)}
                  className={`text-[10px] font-mono px-2 py-1 rounded ${tab === t ? 'bg-primary text-primary-foreground' : 'bg-surface text-gray-400 border border-border'}`}>
            {t === 'cves' ? 'RECENT CVEs' : 'MITRE ATT&CK'}
          </button>
        ))}
      </div>
      <div className="flex-1 min-h-0">
        {tab === 'cves' ? <CvesTab feed={feed} onRefresh={() => load(true)} /> : <MitreTab initial={feed?.mitre_techniques ?? []} />}
      </div>
    </div>
  );
}
