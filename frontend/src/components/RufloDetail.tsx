// RufloDetail — modal with full ruflo telemetry per kind.
import { useEffect, useState } from 'react';
import { X, Database, Network, Brain, Zap, Search } from 'lucide-react';
import { api, type RufloSummary, type RufloPattern } from '@/lib/api';

export type DetailKind = 'hooks' | 'memory' | 'swarms' | 'neural' | 'patterns';

interface Props {
  kind: DetailKind | null;
  onClose: () => void;
}

export function RufloDetail({ kind, onClose }: Props) {
  const [summary, setSummary] = useState<RufloSummary | null>(null);
  const [patterns, setPatterns] = useState<RufloPattern[]>([]);
  const [memoryQuery, setMemoryQuery] = useState('');
  const [memoryResults, setMemoryResults] = useState<
    { id: string; severity: string; vuln_class: string; title: string; score: number }[]
  >([]);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (!kind) return;
    let alive = true;
    const tick = async () => {
      try {
        const s = await api.rufloSummary();
        if (!alive) return;
        setSummary(s);
      } catch {
        /* ignore */
      }
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [kind]);

  useEffect(() => {
    if (kind !== 'patterns') return;
    let alive = true;
    (async () => {
      try {
        const r = await api.rufloPatterns();
        if (!alive) return;
        setPatterns(r.results);
      } catch {
        /* ignore */
      }
    })();
    return () => {
      alive = false;
    };
  }, [kind]);

  const doMemorySearch = async () => {
    if (!memoryQuery.trim()) return;
    setSearching(true);
    try {
      const r = await api.rufloMemorySearch(memoryQuery, 25);
      setMemoryResults(r.results);
    } catch {
      /* ignore */
    } finally {
      setSearching(false);
    }
  };

  if (!kind) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-background border border-border rounded-lg shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            {kind === 'hooks' && <Zap className="w-4 h-4 text-primary" />}
            {kind === 'memory' && <Database className="w-4 h-4 text-primary" />}
            {kind === 'swarms' && <Network className="w-4 h-4 text-primary" />}
            {kind === 'neural' && <Brain className="w-4 h-4 text-primary" />}
            {kind === 'patterns' && <Search className="w-4 h-4 text-primary" />}
            <h2 className="text-sm font-bold text-white font-mono uppercase">
              TELEMETRY · {kind}
            </h2>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 font-mono text-xs">
          {kind === 'hooks' && summary && <HooksView s={summary} />}
          {kind === 'memory' && (
            <MemoryView
              stats={summary?.memory ?? null}
              query={memoryQuery}
              setQuery={setMemoryQuery}
              results={memoryResults}
              searching={searching}
              onSearch={doMemorySearch}
            />
          )}
          {kind === 'swarms' && summary && <SwarmsView s={summary} />}
          {kind === 'neural' && summary && <NeuralView s={summary} />}
          {kind === 'patterns' && <PatternsView patterns={patterns} />}
        </div>
      </div>
    </div>
  );
}

function HooksView({ s }: { s: RufloSummary }) {
  const stages = Object.keys(s.hooks.by_stage).sort();
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        <Stat label="pre-task" value={s.hooks.pre} accent="text-primary" />
        <Stat label="post-task" value={s.hooks.post} accent="text-primary" />
        <Stat label="stages" value={stages.length} accent="text-gray-300" />
      </div>
      <div>
        <div className="text-gray-500 uppercase text-[10px] mb-2">by_stage</div>
        {stages.length === 0 ? (
          <div className="text-gray-600">No hooks fired yet — start a scan.</div>
        ) : (
          <div className="space-y-1">
            {stages.map((stage) => (
              <div
                key={stage}
                className="flex items-center gap-2 bg-surface/40 px-2 py-1 rounded"
              >
                <div className="text-gray-400 w-28">{stage}</div>
                <div className="flex-1 bg-background rounded h-2 overflow-hidden">
                  <div
                    className="h-full bg-primary"
                    style={{ width: `${Math.min(100, s.hooks.by_stage[stage] * 10)}%` }}
                  />
                </div>
                <div className="text-primary font-bold w-8 text-right">
                  {s.hooks.by_stage[stage]}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function MemoryView({
  stats,
  query,
  setQuery,
  results,
  searching,
  onSearch,
}: {
  stats: RufloSummary['memory'] | null;
  query: string;
  setQuery: (s: string) => void;
  results: { id: string; severity: string; vuln_class: string; title: string; score: number }[];
  searching: boolean;
  onSearch: () => void;
}) {
  return (
    <div className="space-y-3">
      {stats && (
        <div className="grid grid-cols-4 gap-3">
          <Stat label="findings_indexed" value={stats.findings_indexed} accent="text-yellow-500" />
          <Stat label="patterns_indexed" value={stats.patterns_indexed} accent="text-yellow-500" />
          <Stat label="stores" value={stats.stores} accent="text-gray-300" />
          <Stat label="searches" value={stats.searches} accent="text-gray-300" />
        </div>
      )}
      <div className="flex gap-2">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onSearch()}
          placeholder="search cross-scan memory (e.g. 'apache', 'log4j', 'CVE')"
          className="flex-1 bg-surface border border-border rounded px-2 py-1 text-xs font-mono text-gray-200"
        />
        <button
          onClick={onSearch}
          disabled={searching}
          className="px-3 py-1 bg-primary text-primary-foreground rounded text-xs font-mono uppercase disabled:opacity-50"
        >
          {searching ? '…' : 'search'}
        </button>
      </div>
      <div className="space-y-1">
        {results.length === 0 ? (
          <div className="text-gray-600 text-center py-4">
            {query ? 'no matches' : 'enter a query and press search'}
          </div>
        ) : (
          results.map((r) => (
            <div
              key={r.id}
              className="bg-surface/40 px-2 py-1 rounded flex items-center gap-2"
            >
              <SeverityChip sev={r.severity} />
              <span className="text-gray-500 text-[10px] w-32 truncate">{r.vuln_class}</span>
              <span className="flex-1 text-gray-200">{r.title}</span>
              <span className="text-primary text-[10px]">{r.score.toFixed(2)}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function SwarmsView({ s }: { s: RufloSummary }) {
  const list = Object.entries(s.swarms.swarms).sort(
    (a, b) => (b[1].started_at ?? 0) - (a[1].started_at ?? 0)
  );
  if (list.length === 0) {
    return <div className="text-gray-600 text-center py-4">No swarms registered yet.</div>;
  }
  return (
    <div className="space-y-2">
      {list.map(([id, w]) => (
        <div key={id} className="bg-surface/40 px-3 py-2 rounded">
          <div className="flex items-center justify-between mb-1">
            <div className="text-gray-300 font-bold">{id}</div>
            <span
              className={
                w.status === 'completed'
                  ? 'text-green-500'
                  : w.status === 'running'
                    ? 'text-primary'
                    : 'text-gray-500'
              }
            >
              {w.status.toUpperCase()}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-2 text-[10px] text-gray-500">
            <div>target: <span className="text-gray-300">{w.target}</span></div>
            <div>mode: <span className="text-gray-300">{w.mode}</span></div>
            <div>topology: <span className="text-gray-300">{w.topology}</span></div>
            <div>agents: <span className="text-gray-300">{w.agents?.length ?? 0}</span></div>
            <div>started: <span className="text-gray-300">{new Date(w.started_at * 1000).toLocaleTimeString()}</span></div>
            {w.finished_at && (
              <div>
                finished:{' '}
                <span className="text-gray-300">
                  {new Date(w.finished_at * 1000).toLocaleTimeString()}
                </span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function NeuralView({ s }: { s: RufloSummary }) {
  const agents = Object.entries(s.neural.by_agent).sort((a, b) => a[0].localeCompare(b[0]));
  return (
    <div className="space-y-3">
      <Stat label="trajectory_count" value={s.neural.trajectory_count} accent="text-primary" />
      {agents.length === 0 ? (
        <div className="text-gray-600 text-center py-4">No training steps yet.</div>
      ) : (
        <div className="space-y-1">
          {agents.map(([agent, st]) => (
            <div key={agent} className="bg-surface/40 px-2 py-1 rounded flex items-center gap-2">
              <div className="text-gray-400 w-28">{agent}</div>
              <div className="flex-1 grid grid-cols-4 gap-2 text-[10px]">
                <div>
                  <span className="text-gray-500">n:</span>{' '}
                  <span className="text-gray-300">{st.n}</span>
                </div>
                <div>
                  <span className="text-gray-500">ok:</span>{' '}
                  <span className="text-green-500">{st.ok}</span>
                </div>
                <div>
                  <span className="text-gray-500">fail:</span>{' '}
                  <span className="text-destructive">{st.fail}</span>
                </div>
                <div>
                  <span className="text-gray-500">avg:</span>{' '}
                  <span className="text-primary">{st.avg_dur_s.toFixed(2)}s</span>
                </div>
              </div>
              <div className="text-primary font-bold w-12 text-right">
                {(st.success_rate * 100).toFixed(0)}%
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function PatternsView({ patterns }: { patterns: RufloPattern[] }) {
  if (patterns.length === 0) {
    return <div className="text-gray-600 text-center py-4">No patterns stored yet.</div>;
  }
  return (
    <div className="space-y-1">
      {patterns.slice(0, 50).map((p, i) => (
        <div
          key={i}
          className="bg-surface/40 px-2 py-1 rounded flex items-center gap-2 text-[11px]"
        >
          <span className="text-gray-500 w-32 truncate">{p.agent}</span>
          <span className="text-gray-300 w-40 truncate" title={p.target}>
            {p.target}
          </span>
          <span className="flex-1 text-gray-400">{p.outcome}</span>
          <span className="text-primary">{(p.confidence * 100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="bg-surface/40 px-3 py-2 rounded">
      <div className="text-[10px] text-gray-500 uppercase">{label}</div>
      <div className={`text-lg font-bold ${accent}`}>{value}</div>
    </div>
  );
}

function SeverityChip({ sev }: { sev: string }) {
  const color =
    sev === 'critical'
      ? 'bg-red-500/20 text-red-400 border-red-500/50'
      : sev === 'high'
        ? 'bg-orange-500/20 text-orange-400 border-orange-500/50'
        : sev === 'medium'
          ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
          : sev === 'low'
            ? 'bg-blue-500/20 text-blue-400 border-blue-500/50'
            : 'bg-gray-500/20 text-gray-400 border-gray-500/50';
  return (
    <span className={`text-[9px] uppercase px-1.5 py-0.5 rounded border ${color}`}>{sev}</span>
  );
}
