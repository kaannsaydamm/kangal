import { useEffect, useState } from 'react';
import { Skull, ShieldAlert, Trash2, Plus, CheckCircle, XCircle } from 'lucide-react';
import { api, type Engagement, type ScopeCheckResult } from '@/lib/api';

export function EngagementPanel() {
  const [list, setList] = useState<Record<string, Engagement>>({});
  const [showCreate, setShowCreate] = useState(false);
  const [scopeTarget, setScopeTarget] = useState('');
  const [scopeResult, setScopeResult] = useState<ScopeCheckResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  // form state
  const [name, setName] = useState('');
  const [client, setClient] = useState('');
  const [operator, setOperator] = useState('');
  const [domains, setDomains] = useState('');
  const [cidrs, setCidrs] = useState('');
  const [excluded, setExcluded] = useState('');
  const [profile, setProfile] = useState('full_spectrum');
  const [destructive, setDestructive] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const r = await api.engagementList();
        if (!alive) return;
        setList(r.active);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
      // Always run a baseline scope check on mount so the UI surfaces the
      // active scope baseline immediately. Probe the first engagement's
      // domain if any, otherwise probe localhost so the reason line is
      // visible even before the user creates an engagement.
      try {
        const r = await api.engagementList().catch(() => null);
        const first = r ? Object.values(r.active)[0] : null;
        const probeTarget = first?.scope_domains?.[0] || 'localhost';
        const sc = await api.engagementScopeCheck(probeTarget);
        if (alive) {
          setScopeTarget(probeTarget);
          setScopeResult(sc);
        }
      } catch {
        /* ignore — user can still type and click CHECK */
      }
    })();
    return () => {
      alive = false;
    };
  }, [tick]);

  const refresh = () => setTick((t) => t + 1);

  const submit = async () => {
    if (!name || !client || !operator) {
      setErr('name / client / operator are required');
      return;
    }
    try {
      await api.engagementCreate({
        name,
        client,
        operator,
        scope_domains: domains.split(/[,\s]+/).filter(Boolean),
        scope_cidrs: cidrs.split(/[,\s]+/).filter(Boolean),
        excluded: excluded.split(/[,\s]+/).filter(Boolean),
        profile,
        destructive_allowed: destructive,
      });
      setName('');
      setClient('');
      setOperator('');
      setDomains('');
      setCidrs('');
      setExcluded('');
      setDestructive(false);
      setShowCreate(false);
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const stop = async (id: string) => {
    try {
      await api.engagementStop(id);
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const panic = async (id: string) => {
    if (!confirm('PANIC: stop engagement and kill all its running swarms?')) return;
    try {
      await api.engagementPanic(id);
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const checkScope = async () => {
    if (!scopeTarget.trim()) return;
    try {
      const r = await api.engagementScopeCheck(scopeTarget.trim());
      setScopeResult(r);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const engagements = Object.values(list).sort((a, b) => b.created_at - a.created_at);

  return (
    <div className="border border-border rounded-lg bg-surface/40 p-3 space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono text-gray-400 uppercase flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-yellow-400" />
          Engagements
        </div>
        <button
          onClick={() => setShowCreate((s) => !s)}
          className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary text-primary-foreground flex items-center gap-1"
        >
          <Plus className="w-3 h-3" />
          {showCreate ? 'CANCEL' : 'NEW'}
        </button>
      </div>

      {err && <div className="text-[10px] font-mono text-yellow-500">{err}</div>}

      {showCreate && (
        <div className="space-y-1.5 border-t border-border pt-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="engagement name (e.g. ACME 2026 Q1)"
            className="w-full bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
          />
          <div className="grid grid-cols-2 gap-1.5">
            <input
              value={client}
              onChange={(e) => setClient(e.target.value)}
              placeholder="client"
              className="bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
            />
            <input
              value={operator}
              onChange={(e) => setOperator(e.target.value)}
              placeholder="operator"
              className="bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
            />
          </div>
          <input
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            placeholder="scope domains (comma-separated)"
            className="w-full bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
          />
          <input
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            placeholder="scope CIDRs (comma-separated)"
            className="w-full bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
          />
          <input
            value={excluded}
            onChange={(e) => setExcluded(e.target.value)}
            placeholder="excluded targets (comma-separated)"
            className="w-full bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
          />
          <div className="grid grid-cols-2 gap-1.5">
            <select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              className="bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
            >
              <option value="passive">passive (OSINT only)</option>
              <option value="active">active</option>
              <option value="web_only">web_only</option>
              <option value="network_only">network_only</option>
              <option value="full_spectrum">full_spectrum</option>
            </select>
            <label className="flex items-center gap-1.5 text-[10px] font-mono text-gray-300">
              <input type="checkbox" checked={destructive} onChange={(e) => setDestructive(e.target.checked)} />
              destructive payloads allowed
            </label>
          </div>
          <button
            onClick={submit}
            className="w-full text-[10px] font-mono px-2 py-1 rounded bg-green-500/20 text-green-300 border border-green-500/40"
          >
            CREATE
          </button>
        </div>
      )}

      <div className="space-y-1">
        {engagements.length === 0 ? (
          <div className="text-[10px] font-mono text-gray-600">no active engagements</div>
        ) : (
          engagements.map((e) => (
            <div key={e.id} className="border border-border rounded bg-surface/60 p-2">
              <div className="flex items-center justify-between">
                <div className="text-[11px] font-mono text-gray-200 truncate" title={e.name}>
                  {e.name}
                </div>
                <span
                  className={`text-[9px] font-mono px-1 rounded ${
                    e.status === 'active'
                      ? 'bg-green-500/20 text-green-300 border border-green-500/40'
                      : 'bg-gray-500/20 text-gray-300'
                  }`}
                >
                  {e.status}
                </span>
              </div>
              <div className="text-[9px] font-mono text-gray-500">
                {e.client} · {e.operator} · profile: {e.profile}
                {e.destructive_allowed && <span className="text-red-400 ml-1">· destructive</span>}
              </div>
              <div className="text-[9px] font-mono text-gray-600 truncate" title={e.scope_domains.join(', ')}>
                domains: {e.scope_domains.join(', ') || '—'}
              </div>
              <div className="flex items-center gap-1 mt-1">
                <button
                  onClick={() => stop(e.id)}
                  className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-yellow-500/20 text-yellow-300 border border-yellow-500/40"
                >
                  STOP
                </button>
                <button
                  onClick={() => panic(e.id)}
                  className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40 flex items-center gap-1"
                >
                  <Skull className="w-2.5 h-2.5" />
                  PANIC
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="border-t border-border pt-2 space-y-1.5">
        <div className="text-[10px] font-mono text-gray-400 uppercase">Scope Check</div>
        <div className="flex items-center gap-1">
          <input
            value={scopeTarget}
            onChange={(e) => setScopeTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && checkScope()}
            placeholder="domain or IP"
            className="flex-1 bg-surface/60 border border-border text-xs font-mono text-gray-200 rounded px-2 py-1"
          />
          <button
            onClick={checkScope}
            className="text-[10px] font-mono px-2 py-1 rounded bg-primary text-primary-foreground"
          >
            CHECK
          </button>
        </div>
        {scopeResult && (
          <div
            className={`text-[10px] font-mono flex items-center gap-1 ${
              scopeResult.in_scope ? 'text-green-400' : 'text-red-400'
            }`}
          >
            {scopeResult.in_scope ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
            <span className="truncate">{scopeResult.target}</span>
            <span className="text-gray-500">— {scopeResult.reason}</span>
          </div>
        )}
      </div>
    </div>
  );
}
