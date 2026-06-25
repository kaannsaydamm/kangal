import { useEffect, useMemo, useRef } from 'react';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  useReactFlow,
  type Node,
  type Edge,
  type NodeProps,
  type NodeChange,
  type NodeMouseHandler,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Server, Globe, Network, MapPin, FileCode, Search, Maximize2 } from 'lucide-react';
import type { AssetNode } from '@/lib/api';

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

interface AssetNodeData extends Record<string, unknown> {
  label: string;
  type: string;
  discovered_by: string;
  dim?: boolean;
  selected?: boolean;
}

function AssetNodeView({ data, selected }: NodeProps) {
  const d = data as AssetNodeData;
  const Icon = TYPE_ICONS[d.type] || Globe;
  const color = TYPE_COLORS[d.type] || '#9ca3af';
  return (
    <div
      className={`rounded-md border-2 px-2 py-1.5 bg-background/90 backdrop-blur font-mono text-[11px] min-w-[120px] max-w-[200px] transition-opacity ${
        d.dim ? 'opacity-25' : ''
      }`}
      style={{
        borderColor: color,
        boxShadow: selected ? `0 0 0 2px ${color}, 0 0 12px ${color}` : undefined,
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: color }} />
      <div className="flex items-center gap-1.5">
        <Icon className="w-3 h-3 shrink-0" style={{ color }} />
        <span className="text-[9px] uppercase text-gray-500">{d.type}</span>
      </div>
      <div className="text-gray-200 truncate" title={d.label}>
        {d.label}
      </div>
      <div className="text-[9px] text-gray-600 mt-0.5">by {d.discovered_by}</div>
      <Handle type="source" position={Position.Bottom} style={{ background: color }} />
    </div>
  );
}

const nodeTypes = { asset: AssetNodeView };

const LAYOUT_PREFIX = 'kangal.graphLayout.';

function loadLayout(scanId: string | undefined): Record<string, { x: number; y: number }> {
  if (!scanId) return {};
  try {
    const raw = localStorage.getItem(LAYOUT_PREFIX + scanId);
    if (!raw) return {};
    return JSON.parse(raw) as Record<string, { x: number; y: number }>;
  } catch {
    return {};
  }
}

function saveLayout(scanId: string | undefined, layout: Record<string, { x: number; y: number }>) {
  if (!scanId) return;
  try {
    localStorage.setItem(LAYOUT_PREFIX + scanId, JSON.stringify(layout));
  } catch {
    // ignore quota / private mode
  }
}

interface AssetGraphProps {
  assets: AssetNode[];
  nodes: { id: string; data: { label: string; type: string; discovered_by: string } }[];
  edges: { id: string; source: string; target: string }[];
  scanId?: string;
  search?: string;
  selectedAssetId?: string | null;
  onSelectAsset?: (id: string | null) => void;
}

function GraphInner({
  assets,
  nodes,
  edges,
  scanId,
  search,
  selectedAssetId,
  onSelectAsset,
}: AssetGraphProps) {
  const { fitView } = useReactFlow();
  const layoutRef = useRef<Record<string, { x: number; y: number }>>({});

  // Reload saved layout whenever the scan changes.
  useEffect(() => {
    layoutRef.current = loadLayout(scanId);
  }, [scanId]);

  const searchLower = (search || '').trim().toLowerCase();

  // Auto-layout: tree from root by type depth.
  const layouted = useMemo<Node<AssetNodeData>[]>(() => {
    if (nodes.length === 0) return [];
    const depth: Record<string, number> = {};
    const children: Record<string, string[]> = {};
    for (const a of assets) {
      children[a.parent_id || ''] = children[a.parent_id || ''] || [];
      if (a.parent_id) children[a.parent_id].push(a.id);
    }
    const root = assets.find((a) => !a.parent_id)?.id;
    if (!root) {
      // No root found — fall back to a row.
      return nodes.map((n, i) => ({
        id: n.id,
        type: 'asset',
        position: layoutRef.current[n.id] || { x: (i % 4) * 220, y: Math.floor(i / 4) * 120 },
        data: { ...n.data },
      }));
    }
    const queue: [string, number][] = [[root, 0]];
    while (queue.length) {
      const [id, d] = queue.shift()!;
      depth[id] = d;
      for (const c of children[id] || []) queue.push([c, d + 1]);
    }
    const byDepth: Record<number, string[]> = {};
    for (const [id, d] of Object.entries(depth)) {
      byDepth[d] = byDepth[d] || [];
      byDepth[d].push(id);
    }
    return nodes.map((n) => {
      const d = depth[n.id] || 0;
      const list = byDepth[d] || [];
      const idx = list.indexOf(n.id);
      const auto = { x: (idx - (list.length - 1) / 2) * 220, y: d * 120 };
      return {
        id: n.id,
        type: 'asset',
        position: layoutRef.current[n.id] || auto,
        data: { ...n.data },
      };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, assets, scanId]);

  // Apply search dim + selection highlight on top of the layout.
  const styled: Node<AssetNodeData>[] = useMemo(
    () =>
      layouted.map((n) => {
        const matches =
          !searchLower ||
          n.data.label.toLowerCase().includes(searchLower) ||
          n.data.type.toLowerCase().includes(searchLower) ||
          n.data.discovered_by.toLowerCase().includes(searchLower);
        return {
          ...n,
          selected: n.id === selectedAssetId,
          data: { ...n.data, dim: !!searchLower && !matches, selected: n.id === selectedAssetId },
        };
      }),
    [layouted, searchLower, selectedAssetId],
  );

  const rfEdges: Edge[] = useMemo(
    () => edges.map((e) => ({ id: e.id, source: e.source, target: e.target, animated: true })),
    [edges],
  );

  // Persist drag positions.
  const onNodesChange = (changes: NodeChange[]) => {
    for (const ch of changes) {
      if (ch.type === 'position' && ch.position) {
        layoutRef.current[ch.id] = { x: ch.position.x, y: ch.position.y };
      }
    }
    // Debounce-save on drag end via the dedicated event.
  };
  const onNodeDragStop = () => {
    saveLayout(scanId, layoutRef.current);
  };

  const onClick: NodeMouseHandler = (_e, n) => {
    onSelectAsset?.(n.id);
  };
  const onPaneClick = () => onSelectAsset?.(null);

  return (
    <div className="relative h-full w-full min-h-[400px] bg-background/50">
      <button
        onClick={() => fitView({ padding: 0.15, duration: 250 })}
        className="absolute top-2 right-2 z-10 text-[10px] font-mono px-2 py-1 rounded border border-border bg-surface/80 text-gray-300 hover:bg-surface flex items-center gap-1"
        title="Fit all nodes to view"
      >
        <Maximize2 className="w-3 h-3" /> FIT
      </button>
      <ReactFlow
        nodes={styled}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onNodeDragStop={onNodeDragStop}
        onNodeClick={onClick}
        onPaneClick={onPaneClick}
        fitView
        proOptions={{ hideAttribution: true }}
        minZoom={0.2}
        maxZoom={1.5}
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable
      >
        <Background color="#1f2937" gap={20} />
        <Controls position="bottom-right" />
        <MiniMap
          nodeColor={(n) => TYPE_COLORS[(n.data as { type?: string }).type || ''] || '#9ca3af'}
          maskColor="rgba(0,0,0,0.5)"
          position="bottom-left"
        />
      </ReactFlow>
    </div>
  );
}

export function AssetGraph(props: AssetGraphProps) {
  if (props.assets.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-600 font-mono text-xs">
        <div className="text-center">
          <Search className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <div>No assets yet.</div>
          <div className="text-[10px] mt-1">Run a scan to see the topology.</div>
        </div>
      </div>
    );
  }
  return (
    <ReactFlowProvider>
      <GraphInner {...props} />
    </ReactFlowProvider>
  );
}
