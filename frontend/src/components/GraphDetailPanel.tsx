import { useEffect, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { X, ExternalLink, ShieldAlert, Globe, Server, MapPin, FileCode, Network, Search } from 'lucide-react';
import type { AssetNode, Finding } from '@/lib/api';

const TYPE_ICONS: Record<string, typeof Globe> = {
  domain: Globe,
  subdomain: Network,
  ip: Server,
  port: MapPin,
  service: MapPin,
  url: Globe,
  endpoint: FileCode,
  tech: Search,
};

const TYPE_COLORS: Record<string, string> = {
  domain: '#22d3ee',
  subdomain: '#06b6d4',
  ip: '#a78bfa',
  port: '#facc15',
  service: '#facc15',
  url: '#22c55e',
  endpoint: '#f97316',
  tech: '#d946ef',
};

interface GraphDetailPanelProps {
  asset: AssetNode | null;
  findings: Finding[];
  onClose: () => void;
}

export function GraphDetailPanel({ asset, findings, onClose }: GraphDetailPanelProps) {
  // Used for a tiny "I just opened this" highlight pulse via setState on mount.
  const [, setTick] = useState(0);
  useEffect(() => {
    if (asset) setTick((t) => t + 1);
  }, [asset]);

  if (!asset) return null;
  const Icon = TYPE_ICONS[asset.type] || Globe;
  const color = TYPE_COLORS[asset.type] || '#9ca3af';

  const related = findings.filter((f) => f.asset_id === asset.id);

  return (
    <Dialog.Root
      open={!!asset}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <Dialog.Portal>
        {/* No overlay — keep the graph interactive behind the drawer */}
        <Dialog.Content
          className="fixed right-0 top-0 z-50 h-full w-[min(420px,90vw)] border-l border-border bg-surface shadow-2xl outline-none flex flex-col"
        >
          <div className="flex items-start justify-between border-b border-border px-5 py-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <Icon className="w-4 h-4 shrink-0" style={{ color }} />
                <span
                  className="text-[10px] font-mono uppercase tracking-widest"
                  style={{ color }}
                >
                  {asset.type}
                </span>
              </div>
              <Dialog.Title className="text-sm font-mono text-gray-200 truncate mt-1" title={asset.value}>
                {asset.value}
              </Dialog.Title>
              {asset.discovered_by && (
                <div className="text-[10px] font-mono text-gray-500 mt-0.5">
                  discovered by <span className="text-gray-300">{asset.discovered_by}</span>
                </div>
              )}
            </div>
            <Dialog.Close asChild>
              <button
                aria-label="Close"
                className="text-gray-500 hover:text-gray-200 ml-2"
              >
                <X className="w-4 h-4" />
              </button>
            </Dialog.Close>
          </div>

          <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5 text-xs font-mono">
            {/* meta */}
            {Object.keys(asset.meta || {}).length > 0 && (
              <section>
                <h3 className="text-[10px] uppercase tracking-widest text-gray-500 mb-1.5">
                  Meta
                </h3>
                <pre className="bg-background/60 border border-border rounded p-2 text-[10px] text-gray-300 overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(asset.meta, null, 2)}
                </pre>
              </section>
            )}

            {/* hierarchy */}
            <section>
              <h3 className="text-[10px] uppercase tracking-widest text-gray-500 mb-1.5">
                Hierarchy
              </h3>
              <div className="grid grid-cols-2 gap-2 text-[10px]">
                <div className="bg-background/40 border border-border rounded px-2 py-1.5">
                  <div className="text-gray-500">id</div>
                  <div className="text-gray-200 truncate" title={asset.id}>
                    {asset.id}
                  </div>
                </div>
                <div className="bg-background/40 border border-border rounded px-2 py-1.5">
                  <div className="text-gray-500">parent</div>
                  <div className="text-gray-200 truncate" title={asset.parent_id || '—'}>
                    {asset.parent_id || '— (root)'}
                  </div>
                </div>
              </div>
            </section>

            {/* findings */}
            <section>
              <h3 className="text-[10px] uppercase tracking-widest text-gray-500 mb-1.5 flex items-center gap-1.5">
                <ShieldAlert className="w-3 h-3" /> Findings
                <span className="text-gray-600">({related.length})</span>
              </h3>
              {related.length === 0 ? (
                <div className="text-[10px] text-gray-600 italic">No findings linked to this asset.</div>
              ) : (
                <ul className="space-y-2">
                  {related.map((f) => {
                    const sev =
                      f.severity === 'critical'
                        ? 'bg-red-500/20 text-red-300 border-red-700'
                        : f.severity === 'high'
                          ? 'bg-orange-500/20 text-orange-300 border-orange-700'
                          : f.severity === 'medium'
                            ? 'bg-yellow-500/20 text-yellow-300 border-yellow-700'
                            : 'bg-gray-500/20 text-gray-300 border-gray-700';
                    return (
                      <li
                        key={f.id}
                        className="border border-border rounded px-2 py-1.5 bg-background/40"
                      >
                        <div className="flex items-center gap-1.5 mb-1">
                          <span
                            className={`text-[9px] uppercase px-1.5 py-0.5 rounded border ${sev}`}
                          >
                            {f.severity}
                          </span>
                          <span className="text-[10px] text-gray-400">{f.vuln_class}</span>
                        </div>
                        <div className="text-gray-200">{f.title}</div>
                        {f.evidence && Object.keys(f.evidence).length > 0 && (
                          <pre className="mt-1.5 text-[9px] text-gray-400 bg-background/60 border border-border rounded p-1.5 overflow-x-auto whitespace-pre-wrap break-all">
                            {JSON.stringify(f.evidence, null, 2)}
                          </pre>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>

            {/* quick actions */}
            <section>
              <h3 className="text-[10px] uppercase tracking-widest text-gray-500 mb-1.5">
                Quick actions
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {(['domain', 'subdomain'].includes(asset.type) ||
                  /^[a-z]/i.test(asset.value)) && (
                  <a
                    href={`https://${asset.value}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] px-2 py-1 rounded border border-border bg-surface text-gray-300 hover:bg-surface/60 flex items-center gap-1"
                  >
                    <ExternalLink className="w-3 h-3" /> open
                  </a>
                )}
                {asset.type === 'ip' && (
                  <a
                    href={`https://ipinfo.io/${asset.value}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[10px] px-2 py-1 rounded border border-border bg-surface text-gray-300 hover:bg-surface/60 flex items-center gap-1"
                  >
                    <ExternalLink className="w-3 h-3" /> ipinfo
                  </a>
                )}
              </div>
            </section>
          </div>

          <div className="border-t border-border px-5 py-2 text-[10px] font-mono text-gray-500">
            Press <span className="text-gray-300">Esc</span> or click outside to close
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
