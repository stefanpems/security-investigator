/**
 * Sentinel Geo Map MCP Server
 * 
 * Provides a tool for visualizing Sentinel security data as an interactive geo map.
 * Uses Leaflet.js for CSP-compliant map rendering.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ReadResourceResult } from "@modelcontextprotocol/sdk/types.js";
import fs from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import {
  RESOURCE_MIME_TYPE,
  registerAppResource,
  registerAppTool,
} from "@modelcontextprotocol/ext-apps/server";

// Works both from source (server.ts) and compiled (dist/server.js)
const DIST_DIR = import.meta.filename.endsWith(".ts")
  ? path.join(import.meta.dirname, "dist")
  : import.meta.dirname;

// Schema for map marker data
const MapMarkerSchema = z.object({
  ip: z.string().describe("IP address (used for enrichment lookup)"),
  lat: z.number().describe("Latitude coordinate"),
  lon: z.number().describe("Longitude coordinate"),
  value: z.number().describe("Numeric value (e.g., attack count, sign-in count)"),
  label: z.string().optional().describe("Optional label for the marker (defaults to IP)"),
});

// Schema for IP enrichment data (optional)
const EnrichmentSchema = z.object({
  ip: z.string().describe("IP address"),
  city: z.string().optional().describe("City location"),
  country: z.string().optional().describe("Country code"),
  org: z.string().optional().describe("ISP/Organization"),
  is_vpn: z.boolean().optional().describe("VPN detected"),
  is_proxy: z.boolean().optional().describe("Proxy detected"),
  is_tor: z.boolean().optional().describe("Tor exit node"),
  abuse_confidence_score: z.number().optional().describe("AbuseIPDB confidence score 0-100"),
  total_reports: z.number().optional().describe("Total AbuseIPDB reports"),
  last_reported: z.string().optional().describe("Last report date"),
  threat_categories: z.array(z.string()).optional().describe("Threat categories from reports"),
});

// Schema for the full geo map data input
const GeoMapDataInputSchema = z.object({
  data: z.array(MapMarkerSchema).describe("Array of map markers with IP, coordinates, and value"),
  title: z.string().optional().default("Attack Origin Map").describe("Title displayed above the map"),
  valueLabel: z.string().optional().default("Attacks").describe("Label for marker values (e.g., 'Attacks', 'Sign-ins')"),
  colorScale: z.enum(["green-red", "blue-red", "blue-yellow"]).optional().default("blue-red")
    .describe("Color scale for markers: green-red, blue-red (threats), blue-yellow"),
  enrichment: z.array(EnrichmentSchema).optional().describe("Optional IP enrichment data for clickable drill-down"),
});

// Output schema for structured content
const GeoMapOutputSchema = z.object({
  data: z.array(MapMarkerSchema),
  title: z.string(),
  valueLabel: z.string(),
  colorScale: z.string(),
  stats: z.object({
    totalMarkers: z.number(),
    totalValue: z.number(),
    maxValue: z.number(),
    minValue: z.number(),
    uniqueCountries: z.number(),
  }),
  generatedAt: z.string(),
  enrichment: z.array(EnrichmentSchema).optional(),
});

function computeStats(data: z.infer<typeof MapMarkerSchema>[], enrichment?: z.infer<typeof EnrichmentSchema>[]) {
  const values = data.map(d => d.value);
  const countries = new Set<string>();
  
  if (enrichment) {
    data.forEach(marker => {
      const enrich = enrichment.find(e => e.ip === marker.ip);
      if (enrich?.country) {
        countries.add(enrich.country);
      }
    });
  }
  
  return {
    totalMarkers: data.length,
    totalValue: values.reduce((a, b) => a + b, 0),
    maxValue: values.length > 0 ? Math.max(...values) : 0,
    minValue: values.length > 0 ? Math.min(...values) : 0,
    uniqueCountries: countries.size,
  };
}

function formatSummary(
  data: z.infer<typeof MapMarkerSchema>[],
  title: string,
  valueLabel: string,
  stats: ReturnType<typeof computeStats>
): string {
  return `${title}
Unique IPs: ${stats.totalMarkers}
Countries: ${stats.uniqueCountries}
Total ${valueLabel}: ${stats.totalValue.toLocaleString()}
Peak ${valueLabel}: ${stats.maxValue.toLocaleString()}`;
}

export function createServer(): McpServer {
  const server = new McpServer({
    name: "Sentinel GeoMap Server",
    version: "0.1.0",
  });

  const resourceUri = "ui://show-attack-map/mcp-app.html";

  // Register the geo map visualization tool
  registerAppTool(
    server,
    "show-attack-map",
    {
      title: "Show Attack Origin Map",
      description: `Displays Sentinel security data as an interactive geo map visualization.
Pass IP addresses with coordinates and values from KQL queries or enrichment data.
Supports click-to-expand threat intelligence panels when enrichment data is provided.`,
      inputSchema: GeoMapDataInputSchema.shape,
      outputSchema: GeoMapOutputSchema.shape,
      _meta: { ui: { resourceUri } },
    },
    async ({ data, title, valueLabel, colorScale, enrichment }) => {
      const stats = computeStats(data, enrichment);
      
      return {
        content: [
          { 
            type: "text", 
            text: formatSummary(data, title, valueLabel, stats) 
          }
        ],
        structuredContent: {
          data,
          title,
          valueLabel,
          colorScale,
          stats,
          generatedAt: new Date().toISOString(),
          enrichment,
        },
      };
    }
  );

  // Register the HTML resource for the geo map UI
  registerAppResource(
    server,
    resourceUri,
    resourceUri,
    { mimeType: RESOURCE_MIME_TYPE },
    async (): Promise<ReadResourceResult> => {
      const html = await fs.readFile(
        path.join(DIST_DIR, "index.html"),
        "utf-8"
      );
      return {
        contents: [
          {
            uri: resourceUri,
            mimeType: RESOURCE_MIME_TYPE,
            text: html,
          },
        ],
      };
    }
  );

  return server;
}
