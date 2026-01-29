/**
 * Sentinel Geo Map React Component
 * 
 * Renders an interactive SVG world map for visualizing attack origins.
 * Uses embedded SVG paths from SimpleMaps (MIT licensed) - no external dependencies.
 */
import type { McpUiHostContext } from "@modelcontextprotocol/ext-apps";
import { useApp } from "@modelcontextprotocol/ext-apps/react";
import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import "./mcp-app.css";
// Import the world map SVG as raw text
import worldMapSvg from "./world.svg?raw";

// Types matching the server schema
interface MapMarker {
  ip: string;
  lat: number;
  lon: number;
  value: number;
  label?: string;
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

interface GeoMapData {
  data: MapMarker[];
  title: string;
  valueLabel: string;
  colorScale: "green-red" | "blue-red" | "blue-yellow";
  stats: {
    totalMarkers: number;
    totalValue: number;
    maxValue: number;
    minValue: number;
    uniqueCountries: number;
  };
  generatedAt: string;
  enrichment?: EnrichmentData[];
}

// Robinson projection parameters (standard lookup table)
const ROBINSON_AA = [
  0.8487, 0.84751182, 0.84479598, 0.840213, 0.83359314, 0.8257851,
  0.814752, 0.80006949, 0.78216192, 0.76060494, 0.73658673, 0.7086645,
  0.67777182, 0.64475739, 0.60987582, 0.57134484, 0.52729731, 0.48562614, 0.45167814
];
const ROBINSON_BB = [
  0, 0.0838426, 0.1676852, 0.2515278, 0.3353704, 0.419213,
  0.5030556, 0.5868982, 0.67311143, 0.7593250, 0.84553818, 0.93066901,
  1.01436161, 1.09554225, 1.17280746, 1.24610797, 1.31398330, 1.37643138, 1.41421356
];

// Interpolate Robinson projection values
function robinsonInterpolate(table: number[], lat: number): number {
  const absLat = Math.abs(lat);
  const i = Math.min(Math.floor(absLat / 5), 17);
  const fraction = (absLat - i * 5) / 5;
  return table[i] * (1 - fraction) + table[i + 1] * fraction;
}

// Convert lat/lon to Robinson projection coordinates
// Returns x,y in range roughly [-1,1] for x and [-1,1] for y
function robinsonProject(lat: number, lon: number): { x: number; y: number } {
  const lonRad = (lon * Math.PI) / 180;
  const x = robinsonInterpolate(ROBINSON_AA, lat) * lonRad / Math.PI;
  const y = (lat >= 0 ? 1 : -1) * robinsonInterpolate(ROBINSON_BB, lat);
  return { x, y };
}

// Convert lat/lon to SVG coordinates based on Robinson projection
// The SimpleMaps SVG viewBox is "0 0 2000 857" with center at lon=10E
function latLonToSVG(lat: number, lon: number): { x: number; y: number } {
  // The SVG is centered at approximately 10°E
  const centerLon = 10;
  const adjustedLon = lon - centerLon;
  
  const proj = robinsonProject(lat, adjustedLon);
  
  // Map to SVG coordinates (viewBox: 0 0 2000 857)
  // x: -1 to 1 maps to roughly 50 to 1950
  // y: -1 to 1 maps to roughly 50 to 807 (with margin)
  const svgWidth = 2000;
  const svgHeight = 857;
  
  const x = (proj.x + 1) * (svgWidth * 0.475) + svgWidth * 0.025;
  const y = (1 - (proj.y + 1) / 2) * (svgHeight * 0.9) + svgHeight * 0.05;
  
  return { x, y };
}

// Color scale functions
function getMarkerColor(value: number, min: number, max: number, scale: string): string {
  const normalized = max === min ? 1 : (value - min) / (max - min);
  
  switch (scale) {
    case "blue-red":
      const r1 = Math.round(50 + normalized * 205);
      const g1 = Math.round(50 + (1 - normalized) * 50);
      const b1 = Math.round(200 - normalized * 150);
      return `rgb(${r1}, ${g1}, ${b1})`;
      
    case "blue-yellow":
      const r2 = Math.round(normalized * 255);
      const g2 = Math.round(normalized * 220);
      const b2 = Math.round(150 - normalized * 100);
      return `rgb(${r2}, ${g2}, ${b2})`;
      
    case "green-red":
    default:
      const hue = 120 - normalized * 120;
      return `hsl(${hue}, 70%, 45%)`;
  }
}

// Get marker size based on value
function getMarkerSize(value: number, min: number, max: number): number {
  const normalized = max === min ? 1 : (value - min) / (max - min);
  return 6 + normalized * 18;
}

// Enrichment detail panel component
function EnrichmentPanel({ 
  enrichment, 
  selectedIp, 
  onClose 
}: { 
  enrichment: EnrichmentData[]; 
  selectedIp: string; 
  onClose: () => void;
}) {
  const data = enrichment.find(e => e.ip === selectedIp);
  
  if (!data) {
    return (
      <div className="enrichment-panel">
        <div className="enrichment-header">
          <span className="enrichment-title">{selectedIp}</span>
          <button className="enrichment-close" onClick={onClose}>×</button>
        </div>
        <div className="enrichment-body">
          <p className="enrichment-nodata">No enrichment data available for this IP.</p>
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

// Tooltip component
function Tooltip({ x, y, content, visible }: { x: number; y: number; content: string; visible: boolean }) {
  if (!visible) return null;
  
  return (
    <div 
      className="svg-tooltip"
      style={{ 
        left: x + 15, 
        top: y - 10,
        opacity: visible ? 1 : 0
      }}
      dangerouslySetInnerHTML={{ __html: content }}
    />
  );
}

function GeoMap({ data }: { data: GeoMapData }) {
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; content: string; visible: boolean }>({
    x: 0, y: 0, content: '', visible: false
  });
  const mapContainerRef = useRef<HTMLDivElement>(null);
  
  const { minValue, maxValue } = data.stats;
  const hasEnrichment = data.enrichment && data.enrichment.length > 0;
  
  // SimpleMaps SVG viewBox dimensions
  const svgWidth = 2000;
  const svgHeight = 857;
  
  const handleMarkerHover = (marker: MapMarker, event: React.MouseEvent) => {
    const enrichment = data.enrichment?.find(e => e.ip === marker.ip);
    const content = `
      <strong>${marker.ip}</strong><br/>
      ${enrichment ? `${enrichment.city || 'Unknown'}, ${enrichment.country || '??'}<br/>` : ''}
      ${data.valueLabel}: ${marker.value.toLocaleString()}
      ${enrichment?.abuse_confidence_score !== undefined ? `<br/>Abuse Score: ${enrichment.abuse_confidence_score}%` : ''}
    `;
    setTooltip({ 
      x: event.clientX, 
      y: event.clientY, 
      content, 
      visible: true 
    });
  };
  
  const handleMarkerLeave = () => {
    setTooltip(prev => ({ ...prev, visible: false }));
  };

  // Process the SVG to style it for dark theme
  const processedSvg = worldMapSvg
    .replace(/fill="#ececec"/g, 'fill="#2d3a4a"')  // Land color
    .replace(/stroke="black"/g, 'stroke="#4a5a6a"')  // Border color
    .replace(/stroke-width=".2"/g, 'stroke-width="0.5"');  // Slightly thicker borders
  
  return (
    <div className={`geomap-wrapper ${selectedIp ? 'with-panel' : ''}`}>
      <div className="geomap-container">
        <h2 className="geomap-title">{data.title}</h2>
        
        <div className="geomap-stats">
          <span>Unique IPs: <strong>{data.stats.totalMarkers}</strong></span>
          <span>Countries: <strong>{data.stats.uniqueCountries}</strong></span>
          <span>Total {data.valueLabel}: <strong>{data.stats.totalValue.toLocaleString()}</strong></span>
          <span>Peak: <strong>{data.stats.maxValue.toLocaleString()}</strong></span>
          {hasEnrichment && <span className="enrichment-hint-inline">Click marker for threat intel →</span>}
        </div>
        
        <div className="map-container" ref={mapContainerRef}>
          <svg 
            viewBox={`0 0 ${svgWidth} ${svgHeight}`} 
            className="world-map-svg"
            preserveAspectRatio="xMidYMid meet"
          >
            {/* Ocean background */}
            <rect x="0" y="0" width={svgWidth} height={svgHeight} fill="#1a1a2e" />
            
            {/* Embedded world map from SimpleMaps (MIT license) */}
            <g dangerouslySetInnerHTML={{ __html: processedSvg.replace(/<\?xml[^?]*\?>/, '').replace(/<svg[^>]*>/, '').replace(/<\/svg>/, '') }} />
            
            {/* Attack markers overlay */}
            {data.data.map((marker) => {
              const { x, y } = latLonToSVG(marker.lat, marker.lon);
              const color = getMarkerColor(marker.value, minValue, maxValue, data.colorScale);
              const size = getMarkerSize(marker.value, minValue, maxValue) * 2.5; // Scale for larger SVG
              
              return (
                <g key={marker.ip}>
                  {/* Pulse animation ring */}
                  <circle
                    cx={x}
                    cy={y}
                    r={size * 1.5}
                    fill="none"
                    stroke={color}
                    strokeWidth="2"
                    opacity="0.4"
                    className="pulse-ring"
                  />
                  {/* Main marker */}
                  <circle
                    cx={x}
                    cy={y}
                    r={size}
                    fill={color}
                    stroke="#ffffff"
                    strokeWidth="3"
                    opacity="0.9"
                    style={{ cursor: hasEnrichment ? 'pointer' : 'default' }}
                    onClick={() => hasEnrichment && setSelectedIp(selectedIp === marker.ip ? null : marker.ip)}
                    onMouseEnter={(e) => handleMarkerHover(marker, e)}
                    onMouseLeave={handleMarkerLeave}
                    className={selectedIp === marker.ip ? 'marker-selected' : ''}
                  />
                  {/* Value label for large markers */}
                  {size > 30 && (
                    <text
                      x={x}
                      y={y + 8}
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize="20"
                      fontWeight="bold"
                      style={{ pointerEvents: 'none' }}
                    >
                      {marker.value > 999 ? `${Math.round(marker.value / 1000)}k` : marker.value}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
          
          <Tooltip {...tooltip} />
        </div>
        
        <div className="geomap-legend">
          <span className="legend-label">Low ({minValue})</span>
          <div className="legend-gradient" style={{
            background: data.colorScale === "blue-red" 
              ? "linear-gradient(to right, rgb(50,100,200), rgb(255,50,50))"
              : data.colorScale === "blue-yellow"
              ? "linear-gradient(to right, rgb(0,0,150), rgb(255,220,50))"
              : "linear-gradient(to right, hsl(120,70%,45%), hsl(0,70%,45%))"
          }} />
          <span className="legend-label">High ({maxValue})</span>
        </div>
        
        <div className="geomap-footer">
          Map: SimpleMaps.com (MIT) | Generated: {new Date(data.generatedAt).toLocaleString()}
        </div>
      </div>
      
      {selectedIp && hasEnrichment && (
        <EnrichmentPanel 
          enrichment={data.enrichment!}
          selectedIp={selectedIp}
          onClose={() => setSelectedIp(null)}
        />
      )}
    </div>
  );
}

function App() {
  const [data, setData] = useState<GeoMapData | null>(null);
  const [hostContext, setHostContext] = useState<McpUiHostContext | undefined>();
  
  const { app, error } = useApp({
    appInfo: { name: "Sentinel GeoMap", version: "0.1.0" },
    capabilities: {},
    onAppCreated: (app) => {
      app.ontoolresult = (params) => {
        if (params.structuredContent) {
          setData(params.structuredContent as unknown as GeoMapData);
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
        <span>Waiting for map data...</span>
      </div>
    );
  }
  
  if (!data.data || data.data.length === 0) {
    return (
      <div className="empty">
        <span>No map data provided</span>
      </div>
    );
  }
  
  return <GeoMap data={data} />;
}

// Mount the app
const container = document.getElementById("root");
if (container) {
  const root = createRoot(container);
  root.render(<App />);
}
