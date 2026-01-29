/**
 * Sentinel Sign-In Heatmap React Component
 * 
 * Renders an interactive heatmap visualization for Sentinel sign-in data.
 */
import type { App, McpUiHostContext } from "@modelcontextprotocol/ext-apps";
import { useApp } from "@modelcontextprotocol/ext-apps/react";
import React, { useMemo, useState, useEffect, useCallback } from "react";
import { createRoot } from "react-dom/client";
import "./mcp-app.css";

// Types matching the server schema
interface HeatmapCell {
  row: string;
  column: string;
  value: number;
}

interface EnrichmentData {
  ip: string;
  city?: string;
  country?: string;
  org?: string;
  is_vpn?: boolean;
  is_proxy?: boolean;
  is_tor?: boolean;
  abuse_confidence_score?: number;
  total_reports?: number;
  last_reported?: string;
  threat_categories?: string[];
}

interface HeatmapData {
  data: HeatmapCell[];
  title: string;
  rowLabel: string;
  colLabel: string;
  valueLabel: string;
  colorScale: "green-red" | "blue-red" | "blue-yellow";
  stats: {
    totalCells: number;
    totalValue: number;
    maxValue: number;
    minValue: number;
    uniqueRows: number;
    uniqueCols: number;
  };
  generatedAt: string;
  enrichment?: EnrichmentData[];
}

// Color scale functions
function getColor(value: number, min: number, max: number, scale: string): string {
  // No data = neutral dark gray
  if (value === 0) {
    return "#2a2a2a";
  }
  
  // Normalize between min (non-zero) and max
  const effectiveMin = min === 0 ? 1 : min;
  const normalized = max === effectiveMin ? 1 : (value - effectiveMin) / (max - effectiveMin);
  
  switch (scale) {
    case "blue-red":
      // Low = blue (safe), High = red (threat) - good for failed attempts/threats
      const r1 = Math.round(50 + normalized * 205);
      const g1 = Math.round(50 + (1 - normalized) * 50);
      const b1 = Math.round(200 - normalized * 150);
      return `rgb(${r1}, ${g1}, ${b1})`;
      
    case "blue-yellow":
      // Neutral scale - dark blue to bright yellow
      const r2 = Math.round(normalized * 255);
      const g2 = Math.round(normalized * 220);
      const b2 = Math.round(150 - normalized * 100);
      return `rgb(${r2}, ${g2}, ${b2})`;
      
    case "green-red":
    default:
      // Activity scale: dark teal (low) → bright green (high)
      // Avoid red since it implies "bad" - use teal-to-green for activity counts
      const hue = 120 + (1 - normalized) * 60; // 180 (teal) to 120 (green)
      const saturation = 50 + normalized * 30; // 50% to 80%
      const lightness = 25 + normalized * 25; // 25% to 50%
      return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
  }
}

// Enrichment detail panel component
function EnrichmentPanel({ 
  enrichment, 
  selectedRow, 
  onClose 
}: { 
  enrichment: EnrichmentData[]; 
  selectedRow: string; 
  onClose: () => void;
}) {
  // Extract IP from row label (may have suffix like " (RDP)" or " (IIS)")
  const ipMatch = selectedRow.match(/^[\d.]+/);
  const ip = ipMatch ? ipMatch[0] : selectedRow;
  
  const data = enrichment.find(e => selectedRow.includes(e.ip) || e.ip === ip);
  
  if (!data) {
    return (
      <div className="enrichment-panel">
        <div className="enrichment-header">
          <span className="enrichment-title">{selectedRow}</span>
          <button className="enrichment-close" onClick={onClose}>×</button>
        </div>
        <div className="enrichment-body">
          <p className="enrichment-nodata">No enrichment data available for this IP.</p>
          <p className="enrichment-hint">Pass enrichment data to enable drill-down.</p>
        </div>
      </div>
    );
  }
  
  const getAbuseColor = (score?: number) => {
    if (score === undefined) return "#666";
    if (score >= 80) return "#f65314";
    if (score >= 50) return "#ffbb00";
    if (score >= 25) return "#00a1f1";
    return "#7cbb00";
  };
  
  return (
    <div className="enrichment-panel">
      <div className="enrichment-header">
        <span className="enrichment-title">{data.ip}</span>
        <button className="enrichment-close" onClick={onClose}>×</button>
      </div>
      <div className="enrichment-body">
        <div className="enrichment-location">
          <span className="enrichment-label">Location</span>
          <span className="enrichment-value">
            {data.city || "Unknown"}, {data.country || "??"}
          </span>
        </div>
        
        <div className="enrichment-org">
          <span className="enrichment-label">Organization</span>
          <span className="enrichment-value">{data.org || "Unknown"}</span>
        </div>
        
        <div className="enrichment-flags">
          {data.is_vpn && <span className="flag flag-vpn">VPN</span>}
          {data.is_proxy && <span className="flag flag-proxy">Proxy</span>}
          {data.is_tor && <span className="flag flag-tor">Tor</span>}
        </div>
        
        {data.abuse_confidence_score !== undefined && (
          <div className="enrichment-abuse">
            <span className="enrichment-label">AbuseIPDB Score</span>
            <div className="abuse-meter">
              <div 
                className="abuse-fill" 
                style={{ 
                  width: `${data.abuse_confidence_score}%`,
                  backgroundColor: getAbuseColor(data.abuse_confidence_score)
                }}
              />
              <span className="abuse-score">{data.abuse_confidence_score}%</span>
            </div>
          </div>
        )}
        
        {data.total_reports !== undefined && (
          <div className="enrichment-reports">
            <span className="enrichment-label">Total Reports</span>
            <span className="enrichment-value">{data.total_reports.toLocaleString()}</span>
          </div>
        )}
        
        {data.last_reported && (
          <div className="enrichment-lastreport">
            <span className="enrichment-label">Last Reported</span>
            <span className="enrichment-value">{data.last_reported}</span>
          </div>
        )}
        
        {data.threat_categories && data.threat_categories.length > 0 && (
          <div className="enrichment-threats">
            <span className="enrichment-label">Threat Categories</span>
            <div className="threat-tags">
              {data.threat_categories.slice(0, 5).map((cat, i) => (
                <span key={i} className="threat-tag">{cat}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function HeatmapGrid({ data }: { data: HeatmapData }) {
  const [selectedRow, setSelectedRow] = useState<string | null>(null);
  
  const { rows, columns, cellMap } = useMemo(() => {
    const rowSet = new Set<string>();
    const colSet = new Set<string>();
    const map = new Map<string, number>();
    
    data.data.forEach(cell => {
      rowSet.add(cell.row);
      colSet.add(cell.column);
      map.set(`${cell.row}|${cell.column}`, cell.value);
    });
    
    // Sort rows alphabetically, columns by natural order (assuming time-based)
    const sortedRows = Array.from(rowSet).sort();
    const sortedCols = Array.from(colSet).sort();
    
    return { rows: sortedRows, columns: sortedCols, cellMap: map };
  }, [data.data]);
  
  const { minValue, maxValue } = data.stats;
  const hasEnrichment = data.enrichment && data.enrichment.length > 0;
  
  return (
    <div className={`heatmap-wrapper ${selectedRow ? 'with-panel' : ''}`}>
      <div className="heatmap-container">
        <h2 className="heatmap-title">{data.title}</h2>
        
        <div className="heatmap-stats">
          <span>Total {data.valueLabel}: <strong>{data.stats.totalValue.toLocaleString()}</strong></span>
          <span>Peak: <strong>{maxValue.toLocaleString()}</strong></span>
          <span>{data.rowLabel}s: <strong>{data.stats.uniqueRows}</strong></span>
          <span>{data.colLabel} periods: <strong>{data.stats.uniqueCols}</strong></span>
          {hasEnrichment && <span className="enrichment-hint-inline">Click row for threat intel →</span>}
        </div>
        
        <div className="heatmap-scroll">
          <table className="heatmap-table">
            <thead>
              <tr>
                <th className="corner-cell">{data.rowLabel} / {data.colLabel}</th>
                {columns.map(col => (
                  <th key={col} className="col-header" title={col}>
                    {col.length > 8 ? col.slice(0, 8) + "…" : col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map(row => (
                <tr 
                  key={row} 
                  className={`${selectedRow === row ? 'row-selected' : ''} ${hasEnrichment ? 'row-clickable' : ''}`}
                  onClick={() => hasEnrichment && setSelectedRow(selectedRow === row ? null : row)}
                >
                  <td className="row-header" title={row}>
                    {row.length > 20 ? row.slice(0, 20) + "…" : row}
                  </td>
                  {columns.map(col => {
                    const value = cellMap.get(`${row}|${col}`) ?? 0;
                    const color = getColor(value, minValue, maxValue, data.colorScale);
                    return (
                      <td
                        key={`${row}|${col}`}
                        className="heatmap-cell"
                        style={{ backgroundColor: color }}
                        title={`${row}\n${col}\n${data.valueLabel}: ${value.toLocaleString()}`}
                      >
                        {value > 0 ? value.toLocaleString() : ""}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        <div className="heatmap-legend">
          <span className="legend-label">No data</span>
          <div className="legend-swatch" style={{ backgroundColor: "#2a2a2a" }} />
          <span className="legend-label">Low</span>
          <div className="legend-gradient" style={{
            background: data.colorScale === "blue-red" 
              ? "linear-gradient(to right, rgb(50,100,200), rgb(255,50,50))"
              : data.colorScale === "blue-yellow"
              ? "linear-gradient(to right, rgb(0,0,150), rgb(255,220,50))"
              : "linear-gradient(to right, hsl(180,50%,25%), hsl(120,80%,50%))"
          }} />
          <span className="legend-label">High ({maxValue})</span>
        </div>
        
        <div className="heatmap-footer">
          Generated: {new Date(data.generatedAt).toLocaleString()}
        </div>
      </div>
      
      {selectedRow && hasEnrichment && (
        <EnrichmentPanel 
          enrichment={data.enrichment!}
          selectedRow={selectedRow}
          onClose={() => setSelectedRow(null)}
        />
      )}
    </div>
  );
}

function App() {
  const [data, setData] = useState<HeatmapData | null>(null);
  const [hostContext, setHostContext] = useState<McpUiHostContext | undefined>();
  
  const { app, error } = useApp({
    appInfo: { name: "Sentinel Heatmap", version: "0.1.0" },
    capabilities: {},
    onAppCreated: (app) => {
      // Listen for tool results containing our heatmap data
      app.ontoolresult = (params) => {
        if (params.structuredContent) {
          setData(params.structuredContent as unknown as HeatmapData);
        }
      };
      
      app.onhostcontextchanged = (params) => {
        setHostContext((prev) => ({ ...prev, ...params }));
      };
    },
  });
  
  useEffect(() => {
    if (app) {
      setHostContext(app.getHostContext());
    }
  }, [app]);
  
  if (error) {
    return (
      <div className="error">
        <span>Error: {error.message}</span>
      </div>
    );
  }
  
  if (!app) {
    return (
      <div className="loading">
        <div className="spinner" />
        <span>Connecting...</span>
      </div>
    );
  }
  
  if (!data) {
    return (
      <div className="loading">
        <div className="spinner" />
        <span>Waiting for heatmap data...</span>
      </div>
    );
  }
  
  if (!data.data || data.data.length === 0) {
    return (
      <div className="empty">
        <span>No heatmap data provided</span>
      </div>
    );
  }
  
  return <HeatmapGrid data={data} />;
}

// Mount the app
const container = document.getElementById("root");
if (container) {
  const root = createRoot(container);
  root.render(<App />);
}
