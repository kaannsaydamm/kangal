// RufloStatus — live header strip showing hook/memory/swarm/neural telemetry.
// Polls /api/ruflo/summary every 2s while mounted. Clickable cells open a modal
// with the raw view (hooks, memory, patterns, swarms, neural).
import { useEffect, useState } from 'react';
import { Activity, Brain, Database, Network, Zap, ChevronRight } from 'lucide-react';
import { api, type RufloSummary } from '@/lib/api';

interface Props {
  onOpenDetail?: (kind: 'hooks' | 'memory' | 'swarms' | 'neural' | 'patterns') => void;
}

export function RufloStatus({ onOpenDetail }: Props) {
  const [s, setS] = useState<RufloSummary | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await api.rufloSummary();
        if (!alive) return;
        setS(r);
        setErr(false);
      } catch {
        if (!alive) return;
        setErr(true);
      }
    };
    tick();
    const t = setInterval(tick, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  if (err && !s) {
    return (
      <div className="text-[10px] font-mono text-gray-600 flex items-center gap-1">
        <span className="w-1.5 h-1.5 rounded-full bg-gray-700" />
        RUFLO: offline
      </div>
    );
  }

  if (!s) {
    return (
      <div className="text-[10px] font-mono text-gray-600 flex items-center gap-1">
        <span className="w-1.5 h-1.5 rounded-full bg-gray-700 animate-pulse" />
        RUFLO: …
      </div>
    );
  }

  const hooks = s.hooks;
  const mem = s.memory;
  const swarms = s.swarms;
  const neural = s.neural;
  const activeSwarms = Object.values(swarms.swarms).filter((x) => x.status === 'running').length;
  const totalSwarms = swarms.count;

  return (
    <div className="flex items-center gap-3 text-[10px] font-mono">
      <RufloBadge
        icon={<Zap className="w-3 h-3" />}
        label="hooks"
        value={`${hooks.post}/${hooks.pre}`}
        accent={hooks.pre > 0 ? 'text-primary' : 'text-gray-500'}
        tooltip={
          hooks.pre === 0
            ? 'No hooks yet — start a scan to see them fire'
            : `${hooks.pre} pre-task, ${hooks.post} post-task fired across ${Object.keys(hooks.by_stage).length} stages`
        }
        onClick={() => onOpenDetail?.('hooks')}
      />
      <RufloBadge
        icon={<Database className="w-3 h-3" />}
        label="memory"
        value={`${mem.findings_indexed}`}
        accent="text-yellow-500"
        tooltip={`${mem.findings_indexed} findings + ${mem.patterns_indexed} patterns indexed; ${mem.stores} stores, ${mem.searches} searches`}
        onClick={() => onOpenDetail?.('memory')}
      />
      <RufloBadge
        icon={<Network className="w-3 h-3" />}
        label="swarms"
        value={`${activeSwarms}/${totalSwarms}`}
        accent={activeSwarms > 0 ? 'text-primary' : 'text-gray-500'}
        tooltip={
          totalSwarms === 0
            ? 'No swarms yet'
            : `${activeSwarms} running, ${totalSwarms} total registered`
        }
        onClick={() => onOpenDetail?.('swarms')}
      />
      <RufloBadge
        icon={<Brain className="w-3 h-3" />}
        label="neural"
        value={`${neural.trajectory_count}`}
        accent={neural.trajectory_count > 0 ? 'text-primary' : 'text-gray-500'}
        tooltip={
          neural.trajectory_count === 0
            ? 'No training steps yet'
            : `${neural.trajectory_count} steps across ${Object.keys(neural.by_agent).length} agents`
        }
        onClick={() => onOpenDetail?.('neural')}
      />
    </div>
  );
}

function RufloBadge({
  icon,
  label,
  value,
  accent,
  tooltip,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  accent: string;
  tooltip?: string;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      title={tooltip}
      className="flex items-center gap-1 px-2 py-1 rounded bg-surface/40 border border-border hover:border-primary/50 transition-colors group"
    >
      <span className={accent}>{icon}</span>
      <span className="text-gray-500 uppercase">{label}</span>
      <span className={`${accent} font-bold`}>{value}</span>
      <ChevronRight className="w-3 h-3 text-gray-700 group-hover:text-primary" />
    </button>
  );
}
