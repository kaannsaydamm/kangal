// ReportsView — scan history browser with expandable findings + markdown export.
//
// Each row in the scan list expands to show every finding for that scan
// (severity, evidence, MITRE technique).  Per-scan "Export as Markdown"
// downloads /api/scan/{id}/report.md.  "Export all" downloads a combined
// report (one section per scan).

import { useEffect, useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Download,
  FileText,
  Loader2,
  AlertTriangle,
} from 'lucide-react';

import {
  api,
  getScanReport,
  type Finding,
  type ScanSummary,
} from '@/lib/api';

const SEVERITY_COLORS: Record<Finding['severity'], string> = {
  critical: 'text-red-500',
  high: 'text-red-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  info: 'text-gray-400',
};

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function ReportsView() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [findingsByScan, setFindingsByScan] = useState<Record<string, Finding[]>>({});
  const [loadingFindings, setLoadingFindings] = useState<Set<string>>(new Set());
  const [exporting, setExporting] = useState<string | null>(null);
  const [exportingAll, setExportingAll] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await api.listScans();
        if (alive) setScans(list);
      } catch (e) {
        if (alive) setErr(String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const toggle = async (scanId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(scanId)) {
        next.delete(scanId);
      } else {
        next.add(scanId);
      }
      return next;
    });
    if (!findingsByScan[scanId] && !loadingFindings.has(scanId)) {
      setLoadingFindings((prev) => new Set(prev).add(scanId));
      try {
        const f = await api.getFindings(scanId);
        setFindingsByScan((prev) => ({ ...prev, [scanId]: f }));
      } catch (e) {
        setErr(String(e));
      } finally {
        setLoadingFindings((prev) => {
          const next = new Set(prev);
          next.delete(scanId);
          return next;
        });
      }
    }
  };

  const exportOne = async (scan: ScanSummary) => {
    setExporting(scan.id);
    try {
      const blob = await getScanReport(scan.id);
      const target = scan.target.replace(/[^a-z0-9.-]/gi, '_').slice(0, 40);
      downloadBlob(blob, `kangal-${target}-${scan.id.slice(0, 8)}.md`);
    } catch (e) {
      setErr(String(e));
    } finally {
      setExporting(null);
    }
  };

  const exportAll = async () => {
    setExportingAll(true);
    try {
      // Fetch every scan's report, concatenate into a single blob.
      const parts: string[] = [];
      for (const scan of scans) {
        // eslint-disable-next-line no-await-in-loop
        const blob = await getScanReport(scan.id);
        // eslint-disable-next-line no-await-in-loop
        const text = await blob.text();
        parts.push(text);
        parts.push('\n\n---\n\n');
      }
      const combined = new Blob([parts.join('')], { type: 'text/markdown' });
      const ts = new Date().toISOString().slice(0, 10);
      downloadBlob(combined, `kangal-all-scans-${ts}.md`);
    } catch (e) {
      setErr(String(e));
    } finally {
      setExportingAll(false);
    }
  };

  const totalFindings = useMemo(
    () => Object.values(findingsByScan).reduce((acc, list) => acc + list.length, 0),
    [findingsByScan]
  );

  return (
    <div className="flex flex-col h-full min-h-0 p-3 gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-primary" />
          <span className="text-sm font-mono text-white tracking-widest uppercase">
            Reports
          </span>
          <span className="text-[10px] font-mono text-gray-500">
            {scans.length} scans · {totalFindings} findings loaded
          </span>
        </div>
        <button
          onClick={exportAll}
          disabled={scans.length === 0 || exportingAll}
          className="text-[10px] font-mono px-2 py-1 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-1"
        >
          {exportingAll ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
          EXPORT ALL
        </button>
      </div>

      {err && <div className="text-[10px] font-mono text-destructive">ERR: {err}</div>}

      <div className="flex-1 min-h-0 overflow-y-auto space-y-1 pr-1">
        {scans.map((scan) => {
          const isOpen = expanded.has(scan.id);
          const findings = findingsByScan[scan.id];
          const isLoading = loadingFindings.has(scan.id);
          const exportingThis = exporting === scan.id;
          return (
            <div key={scan.id} className="border border-border rounded bg-surface/40">
              <div className="flex items-center gap-2 px-2 py-1.5">
                <button
                  onClick={() => toggle(scan.id)}
                  className="text-gray-500 hover:text-gray-200"
                  aria-label={isOpen ? 'collapse' : 'expand'}
                >
                  {isOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                </button>
                <span className="text-xs font-mono text-gray-200 truncate flex-1" title={scan.target}>
                  {scan.target}
                </span>
                <span className="text-[9px] font-mono text-gray-500">{scan.mode}</span>
                <span
                  className={`text-[9px] font-mono px-1 rounded ${
                    scan.status === 'completed'
                      ? 'text-primary border border-primary/40'
                      : scan.status === 'failed'
                        ? 'text-destructive border border-destructive/40'
                        : scan.status === 'running'
                          ? 'text-yellow-400 border border-yellow-400/40'
                          : 'text-gray-400 border border-border'
                  }`}
                >
                  {scan.status.toUpperCase()}
                </span>
                <span className="text-[9px] font-mono text-gray-600 w-32 text-right">
                  {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                </span>
                <button
                  onClick={() => exportOne(scan)}
                  disabled={exportingThis}
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-1"
                >
                  {exportingThis ? <Loader2 className="w-3 h-3 animate-spin" /> : <Download className="w-3 h-3" />}
                  EXPORT
                </button>
              </div>
              {isOpen && (
                <div className="border-t border-border px-3 py-2 bg-black/20">
                  {isLoading && (
                    <div className="text-[10px] font-mono text-gray-500 flex items-center gap-1">
                      <Loader2 className="w-3 h-3 animate-spin" /> loading findings…
                    </div>
                  )}
                  {findings && findings.length === 0 && (
                    <div className="text-[10px] font-mono text-gray-600">no findings.</div>
                  )}
                  {findings && findings.length > 0 && (
                    <ul className="space-y-1.5">
                      {findings.map((f) => (
                        <li key={f.id} className="text-[11px] font-mono">
                          <div className="flex items-start gap-2">
                            <AlertTriangle className={`w-3 h-3 mt-0.5 shrink-0 ${SEVERITY_COLORS[f.severity]}`} />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-1.5">
                                <span className={`font-bold ${SEVERITY_COLORS[f.severity]}`}>
                                  [{f.severity.toUpperCase()}]
                                </span>
                                <span className="text-gray-200">{f.title}</span>
                                <span className="text-[9px] text-gray-500">· {f.vuln_class}</span>
                              </div>
                              {f.evidence && Object.keys(f.evidence).length > 0 && (
                                <div className="mt-0.5 text-[10px] text-gray-400 break-all">
                                  {Object.entries(f.evidence)
                                    .slice(0, 3)
                                    .map(([k, v]) => `${k}=${JSON.stringify(v).slice(0, 80)}`)
                                    .join('  ')}
                                </div>
                              )}
                            </div>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {scans.length === 0 && !err && (
          <div className="text-[10px] font-mono text-gray-500 px-2 py-1 text-center">
            no scans recorded yet
          </div>
        )}
      </div>
    </div>
  );
}
