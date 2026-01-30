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
// X multiplier at each 5-degree latitude interval from 0 to 90
const ROBINSON_X = [
  1.0000, 0.9986, 0.9954, 0.9900, 0.9822, 0.9730,
  0.9600, 0.9427, 0.9216, 0.8962, 0.8679, 0.8350,
  0.7986, 0.7597, 0.7186, 0.6732, 0.6213, 0.5722, 0.5322
];
// Y value at each 5-degree latitude interval from 0 to 90
const ROBINSON_Y = [
  0.0000, 0.0620, 0.1240, 0.1860, 0.2480, 0.3100,
  0.3720, 0.4340, 0.4958, 0.5571, 0.6176, 0.6769,
  0.7346, 0.7903, 0.8435, 0.8936, 0.9394, 0.9761, 1.0000
];

// Interpolate Robinson projection values
function robinsonInterpolate(table: number[], absLat: number): number {
  const i = Math.min(Math.floor(absLat / 5), 17);
  const fraction = (absLat - i * 5) / 5;
  return table[i] * (1 - fraction) + table[i + 1] * fraction;
}

// Convert lat/lon to SVG coordinates
// SimpleMaps world.svg: viewBox="0 0 2000 857", Robinson projection centered at ~11°E
function latLonToSVG(lat: number, lon: number): { x: number; y: number } {
  const svgWidth = 2000;
  const svgHeight = 857;
  
  // SimpleMaps SVG is centered at approximately 11°E longitude
  const centerLon = 11;
  
  // Normalize longitude to -180 to 180 range, adjusted for center
  let adjustedLon = lon - centerLon;
  if (adjustedLon > 180) adjustedLon -= 360;
  if (adjustedLon < -180) adjustedLon += 360;
  
  const absLat = Math.abs(lat);
  
  // Get Robinson projection factors
  const xFactor = robinsonInterpolate(ROBINSON_X, absLat);
  const yFactor = robinsonInterpolate(ROBINSON_Y, absLat);
  
  // Apply projection
  // x: longitude scaled by xFactor, mapped to SVG width
  // Map -180 to 180 (adjusted) → 0 to 2000
  const x = svgWidth / 2 + (adjustedLon / 180) * xFactor * (svgWidth / 2) * 0.95;
  
  // y: latitude to y position, with Robinson distortion
  // Map 90 to -90 → 0 to 857 (top to bottom)
  const ySign = lat >= 0 ? -1 : 1;
  const y = svgHeight / 2 + ySign * yFactor * (svgHeight / 2) * 0.88;
  
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

// Selection Panel component for multi-select mode
function SelectionPanel({
  selectedIps,
  enrichment,
  valueLabel,
  data,
  onClear,
  onRemove,
  onInvestigate,
  isSending
}: {
  selectedIps: Set<string>;
  enrichment?: EnrichmentData[];
  valueLabel: string;
  data: MapMarker[];
  onClear: () => void;
  onRemove: (ip: string) => void;
  onInvestigate: () => void;
  isSending: boolean;
}) {
  if (selectedIps.size === 0) return null;
  
  const selectedList = Array.from(selectedIps);
  
  return (
    <div className="selection-panel">
      <div className="selection-header">
        <span className="selection-title">
          <span className="selection-count">{selectedIps.size}</span> IP{selectedIps.size > 1 ? 's' : ''} Selected
        </span>
        <button className="selection-clear" onClick={onClear} title="Clear selection">✕ Clear</button>
      </div>
      
      <div className="selection-list">
        {selectedList.map(ip => {
          const enrich = enrichment?.find(e => e.ip === ip);
          const marker = data.find(m => m.ip === ip);
          return (
            <div key={ip} className="selection-item">
              <div className="selection-item-info">
                <span className="selection-ip">{ip}</span>
                {enrich && (
                  <span className="selection-meta">
                    {enrich.city}, {enrich.country}
                    {enrich.abuse_confidence_score !== undefined && enrich.abuse_confidence_score > 0 && (
                      <span className={`abuse-badge ${enrich.abuse_confidence_score >= 80 ? 'high' : enrich.abuse_confidence_score >= 50 ? 'medium' : 'low'}`}>
                        {enrich.abuse_confidence_score}%
                      </span>
                    )}
                  </span>
                )}
                {marker && <span className="selection-value">{valueLabel}: {marker.value}</span>}
              </div>
              <button className="selection-remove" onClick={() => onRemove(ip)}>×</button>
            </div>
          );
        })}
      </div>
      
      <div className="selection-actions">
        <button 
          className="btn-investigate" 
          onClick={onInvestigate}
          disabled={isSending}
        >
          {isSending ? 'Sending...' : '🔍 Investigate in Chat'}
        </button>
      </div>
    </div>
  );
}

function GeoMap({ data, app }: { data: GeoMapData; app: import("@modelcontextprotocol/ext-apps").App }) {
  // Single-click view panel IP (for enrichment viewing)
  const [viewingIp, setViewingIp] = useState<string | null>(null);
  // Multi-select for investigation
  const [selectedIps, setSelectedIps] = useState<Set<string>>(new Set());
  const [selectionMode, setSelectionMode] = useState(false);
  const [isSending, setIsSending] = useState(false);
  
  const [tooltip, setTooltip] = useState<{ x: number; y: number; content: string; visible: boolean }>({
    x: 0, y: 0, content: '', visible: false
  });
  const mapContainerRef = useRef<HTMLDivElement>(null);
  
  // Zoom and pan state
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  
  const MIN_ZOOM = 1;
  const MAX_ZOOM = 8;
  const ZOOM_STEP = 0.25;
  
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
  
  // Zoom handlers
  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -ZOOM_STEP : ZOOM_STEP;
    const newZoom = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, zoom + delta));
    
    // Zoom toward cursor position
    if (mapContainerRef.current && newZoom !== zoom) {
      const rect = mapContainerRef.current.getBoundingClientRect();
      const cursorX = e.clientX - rect.left;
      const cursorY = e.clientY - rect.top;
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      
      // Adjust pan to zoom toward cursor
      const zoomRatio = newZoom / zoom;
      const newPanX = cursorX - (cursorX - pan.x) * zoomRatio;
      const newPanY = cursorY - (cursorY - pan.y) * zoomRatio;
      
      // Constrain pan to keep map visible
      const maxPan = (newZoom - 1) * Math.max(rect.width, rect.height) / 2;
      setPan({
        x: Math.max(-maxPan, Math.min(maxPan, newPanX - centerX + centerX)),
        y: Math.max(-maxPan, Math.min(maxPan, newPanY - centerY + centerY))
      });
    }
    
    setZoom(newZoom);
  };
  
  const handleZoomIn = () => {
    setZoom(prev => Math.min(MAX_ZOOM, prev + ZOOM_STEP * 2));
  };
  
  const handleZoomOut = () => {
    const newZoom = Math.max(MIN_ZOOM, zoom - ZOOM_STEP * 2);
    setZoom(newZoom);
    // Reset pan if zooming out to 1x
    if (newZoom <= 1) {
      setPan({ x: 0, y: 0 });
    }
  };
  
  const handleResetZoom = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };
  
  // Pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (zoom > 1 && e.button === 0) {
      setIsPanning(true);
      setPanStart({ x: e.clientX, y: e.clientY });
      setPanOffset({ x: pan.x, y: pan.y });
      e.preventDefault();
    }
  };
  
  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning && mapContainerRef.current) {
      const rect = mapContainerRef.current.getBoundingClientRect();
      const maxPan = (zoom - 1) * Math.max(rect.width, rect.height) / 2;
      const dx = e.clientX - panStart.x;
      const dy = e.clientY - panStart.y;
      setPan({
        x: Math.max(-maxPan, Math.min(maxPan, panOffset.x + dx)),
        y: Math.max(-maxPan, Math.min(maxPan, panOffset.y + dy))
      });
    }
  };
  
  const handleMouseUp = () => {
    setIsPanning(false);
  };
  
  const handleMouseLeave = () => {
    setIsPanning(false);
    handleMarkerLeave();
  };
  
  // Toggle IP selection for multi-select mode
  const toggleIpSelection = (ip: string) => {
    setSelectedIps(prev => {
      const next = new Set(prev);
      if (next.has(ip)) {
        next.delete(ip);
      } else {
        next.add(ip);
      }
      return next;
    });
  };
  
  // Handle marker click - different behavior based on mode
  const handleMarkerClick = (ip: string) => {
    if (selectionMode) {
      toggleIpSelection(ip);
    } else {
      // Single view mode - toggle enrichment panel
      setViewingIp(viewingIp === ip ? null : ip);
    }
  };
  
  // Clear all selections
  const clearSelection = () => {
    setSelectedIps(new Set());
  };
  
  // Remove single IP from selection
  const removeFromSelection = (ip: string) => {
    setSelectedIps(prev => {
      const next = new Set(prev);
      next.delete(ip);
      return next;
    });
  };
  
  // Send selected IPs to chat for investigation
  const investigateInChat = async () => {
    if (selectedIps.size === 0 || !app) return;
    
    setIsSending(true);
    try {
      const selectedList = Array.from(selectedIps);
      
      // Build enriched text for each IP
      const enrichmentLines = selectedList.map(ip => {
        const enrich = data.enrichment?.find(e => e.ip === ip);
        const marker = data.data.find(m => m.ip === ip);
        const parts = [ip];
        
        if (enrich) {
          if (enrich.city || enrich.country) {
            parts.push(`(${enrich.city || 'Unknown'}, ${enrich.country || '??'})`);
          }
          if (enrich.org) {
            parts.push(`[${enrich.org}]`);
          }
          if (enrich.abuse_confidence_score !== undefined && enrich.abuse_confidence_score > 0) {
            parts.push(`Abuse: ${enrich.abuse_confidence_score}%`);
          }
          if (enrich.is_vpn) parts.push('VPN');
          if (enrich.is_tor) parts.push('Tor');
          if (enrich.threat_categories && enrich.threat_categories.length > 0) {
            parts.push(`Threats: ${enrich.threat_categories.slice(0, 3).join(', ')}`);
          }
        }
        if (marker) {
          parts.push(`${data.valueLabel}: ${marker.value}`);
        }
        
        return `- ${parts.join(' | ')}`;
      }).join('\n');
      
      // Use map title to provide context (strip common suffixes for cleaner message)
      const cleanTitle = data.title
        .replace(/\s*-\s*(top\s+)?\d+\s*ips?/i, '')  // Remove "- Top 50 IPs" etc
        .replace(/\s*\(\s*top\s+\d+\s*ips?\s*\)/i, '')  // Remove "(Top 50 IPs)" etc
        .replace(/\s*-\s*\d+\s*day\s*analysis/i, '')  // Remove "- 90 Day Analysis"
        .trim();
      
      const message = `Investigate these ${selectedList.length} IP${selectedList.length > 1 ? 's' : ''} from the ${cleanTitle || 'map'}:\n\n${enrichmentLines}`;
      
      // Send as user message to trigger LLM response
      await app.sendMessage({
        role: "user",
        content: [{ type: "text", text: message }]
      });
      
      // Clear selection after sending
      clearSelection();
      setSelectionMode(false);
    } catch (err) {
      console.error('Failed to send message:', err);
    } finally {
      setIsSending(false);
    }
  };

  // Generate graticule lines (latitude/longitude grid)
  const generateGraticule = () => {
    const lines: JSX.Element[] = [];
    const strokeColor = "rgba(100, 140, 180, 0.15)";
    const strokeWidth = 0.8 / zoom;
    
    // Latitude lines (every 30 degrees)
    for (let lat = -60; lat <= 60; lat += 30) {
      const points: string[] = [];
      for (let lon = -180; lon <= 180; lon += 5) {
        const { x, y } = latLonToSVG(lat, lon);
        points.push(`${x},${y}`);
      }
      lines.push(
        <polyline
          key={`lat-${lat}`}
          points={points.join(' ')}
          fill="none"
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
      );
    }
    
    // Longitude lines (every 30 degrees)
    for (let lon = -180; lon <= 180; lon += 30) {
      const points: string[] = [];
      for (let lat = -85; lat <= 85; lat += 5) {
        const { x, y } = latLonToSVG(lat, lon);
        points.push(`${x},${y}`);
      }
      lines.push(
        <polyline
          key={`lon-${lon}`}
          points={points.join(' ')}
          fill="none"
          stroke={strokeColor}
          strokeWidth={strokeWidth}
        />
      );
    }
    
    return lines;
  };

  // Process the SVG to apply varied country colors for visual depth
  // Use different shades based on country code hash for natural variation
  const processedSvg = worldMapSvg
    .replace(/<\?xml[^?]*\?>/g, '')
    .replace(/<svg[^>]*>/g, '')
    .replace(/<\/svg>/g, '')
    .replace(/fill="#ececec"/g, '')  // Remove default fill - we'll add per-country
    .replace(/stroke="black"/g, 'stroke="#3a4a5a"')
    .replace(/stroke-width=".2"/g, 'stroke-width="0.4"')
    // Apply varied green-blue-gray earth tones to countries based on ID patterns
    .replace(/id="([A-Z]{2})"/g, (match, code) => {
      // Hash country code to get consistent but varied colors
      const hash = (code.charCodeAt(0) * 31 + code.charCodeAt(1)) % 6;
      const colors = [
        '#2a4a3a', // dark forest green
        '#3a4a4a', // blue-gray
        '#2d4a4d', // teal-gray
        '#384a3d', // sage green
        '#334455', // steel blue
        '#2f4a42', // sea green
      ];
      return `id="${code}" fill="${colors[hash]}"`;
    })
    // Handle paths without explicit ID (generic land)
    .replace(/<path(?![^>]*fill=)[^>]*>/g, (match) => {
      if (!match.includes('fill=')) {
        return match.replace('<path', '<path fill="#2d4a44"');
      }
      return match;
    });
  
  const showPanel = viewingIp || (selectionMode && selectedIps.size > 0);
  
  return (
    <div className={`geomap-wrapper ${showPanel ? 'with-panel' : ''}`}>
      <div className="geomap-container">
        <h2 className="geomap-title">{data.title}</h2>
        
        <div className="geomap-stats">
          <span>Unique IPs: <strong>{data.stats.totalMarkers}</strong></span>
          <span>Countries: <strong>{data.stats.uniqueCountries}</strong></span>
          <span>Total {data.valueLabel}: <strong>{data.stats.totalValue.toLocaleString()}</strong></span>
          <span>Peak: <strong>{data.stats.maxValue.toLocaleString()}</strong></span>
          {hasEnrichment && !selectionMode && <span className="enrichment-hint-inline">Click marker for threat intel →</span>}
          {selectionMode && <span className="selection-hint-inline">Click markers to select for investigation</span>}
        </div>
        
        {/* Selection Mode Toggle */}
        <div className="mode-toggle">
          <button 
            className={`mode-btn ${!selectionMode ? 'active' : ''}`}
            onClick={() => { setSelectionMode(false); clearSelection(); }}
          >
            👁 View
          </button>
          <button 
            className={`mode-btn ${selectionMode ? 'active' : ''}`}
            onClick={() => { setSelectionMode(true); setViewingIp(null); }}
          >
            ☑ Select
          </button>
        </div>
        
        <div 
          className={`map-container ${isPanning ? 'panning' : ''} ${zoom > 1 ? 'zoomed' : ''}`}
          ref={mapContainerRef}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseLeave}
        >
          {/* Zoom Controls */}
          <div className="zoom-controls">
            <button className="zoom-btn" onClick={handleZoomIn} title="Zoom In">+</button>
            <span className="zoom-level">{Math.round(zoom * 100)}%</span>
            <button className="zoom-btn" onClick={handleZoomOut} title="Zoom Out">−</button>
            {zoom > 1 && (
              <button className="zoom-btn reset" onClick={handleResetZoom} title="Reset Zoom">⟲</button>
            )}
          </div>
          
          <svg 
            viewBox={`0 0 ${svgWidth} ${svgHeight}`} 
            className="world-map-svg"
            preserveAspectRatio="xMidYMid meet"
            style={{
              transform: `scale(${zoom}) translate(${pan.x / zoom}px, ${pan.y / zoom}px)`,
              transformOrigin: 'center center'
            }}
          >
            {/* Gradient definitions */}
            <defs>
              {/* Ocean gradient - deep blue with subtle variation */}
              <radialGradient id="oceanGradient" cx="50%" cy="40%" r="70%" fx="50%" fy="30%">
                <stop offset="0%" stopColor="#1a3a5c" />
                <stop offset="50%" stopColor="#0d2840" />
                <stop offset="100%" stopColor="#061828" />
              </radialGradient>
              {/* Subtle glow for markers */}
              <filter id="markerGlow" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            
            {/* Ocean background with gradient */}
            <rect x="0" y="0" width={svgWidth} height={svgHeight} fill="url(#oceanGradient)" />
            
            {/* Graticule (lat/lon grid lines) */}
            <g className="graticule">
              {generateGraticule()}
            </g>
            
            {/* Embedded world map from SimpleMaps (MIT license) */}
            <g className="countries" dangerouslySetInnerHTML={{ __html: processedSvg }} />
            
            {/* Attack markers overlay - scale inversely with zoom for consistent visual size */}
            {data.data.map((marker) => {
              const { x, y } = latLonToSVG(marker.lat, marker.lon);
              const color = getMarkerColor(marker.value, minValue, maxValue, data.colorScale);
              const baseSize = getMarkerSize(marker.value, minValue, maxValue) * 2.5;
              // Scale markers inversely with zoom so they stay consistent visual size
              const size = baseSize / zoom;
              const strokeWidth = 2.5 / zoom;
              const pulseStrokeWidth = 1.5 / zoom;
              const fontSize = 18 / zoom;
              
              return (
                <g key={marker.ip} filter="url(#markerGlow)">
                  {/* Outer glow ring */}
                  <circle
                    cx={x}
                    cy={y}
                    r={size * 2}
                    fill="none"
                    stroke={color}
                    strokeWidth={pulseStrokeWidth}
                    opacity="0.2"
                  />
                  {/* Pulse animation ring */}
                  <circle
                    cx={x}
                    cy={y}
                    r={size * 1.4}
                    fill="none"
                    stroke={color}
                    strokeWidth={pulseStrokeWidth}
                    opacity="0.4"
                    className="pulse-ring"
                  />
                  {/* Main marker with gradient-like effect */}
                  <circle
                    cx={x}
                    cy={y}
                    r={size}
                    fill={color}
                    stroke={selectedIps.has(marker.ip) ? '#00ff88' : viewingIp === marker.ip ? '#ffbb00' : 'rgba(255,255,255,0.8)'}
                    strokeWidth={selectedIps.has(marker.ip) || viewingIp === marker.ip ? 4 / zoom : strokeWidth}
                    opacity="0.95"
                    style={{ cursor: hasEnrichment || selectionMode ? 'pointer' : 'default' }}
                    onClick={() => (hasEnrichment || selectionMode) && handleMarkerClick(marker.ip)}
                    onMouseEnter={(e) => handleMarkerHover(marker, e)}
                    onMouseLeave={handleMarkerLeave}
                    className={`${viewingIp === marker.ip ? 'marker-viewing' : ''} ${selectedIps.has(marker.ip) ? 'marker-selected' : ''}`}
                  />
                  {/* Selection checkmark */}
                  {selectedIps.has(marker.ip) && (
                    <text
                      x={x}
                      y={y + 5 / zoom}
                      textAnchor="middle"
                      fill="#00ff88"
                      fontSize={20 / zoom}
                      fontWeight="bold"
                      style={{ pointerEvents: 'none' }}
                    >
                      ✓
                    </text>
                  )}
                  {/* Inner highlight for 3D effect */}
                  <circle
                    cx={x - size * 0.25}
                    cy={y - size * 0.25}
                    r={size * 0.35}
                    fill="rgba(255,255,255,0.3)"
                    style={{ pointerEvents: 'none' }}
                  />
                  {/* Value label for large markers */}
                  {baseSize > 30 && (
                    <text
                      x={x}
                      y={y + 6 / zoom}
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize={fontSize}
                      fontWeight="bold"
                      style={{ pointerEvents: 'none', textShadow: '0 1px 2px rgba(0,0,0,0.8)' }}
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
      
      {/* Enrichment Panel (View Mode) */}
      {viewingIp && hasEnrichment && !selectionMode && (
        <EnrichmentPanel 
          enrichment={data.enrichment!}
          selectedIp={viewingIp}
          onClose={() => setViewingIp(null)}
        />
      )}
      
      {/* Selection Panel (Select Mode) */}
      {selectionMode && (
        <SelectionPanel
          selectedIps={selectedIps}
          enrichment={data.enrichment}
          valueLabel={data.valueLabel}
          data={data.data}
          onClear={clearSelection}
          onRemove={removeFromSelection}
          onInvestigate={investigateInChat}
          isSending={isSending}
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
  
  return <GeoMap data={data} app={app} />;
}

// Mount the app
const container = document.getElementById("root");
if (container) {
  const root = createRoot(container);
  root.render(<App />);
}
