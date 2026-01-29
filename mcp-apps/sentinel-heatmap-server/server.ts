/**
 * Sentinel Sign-In Heatmap MCP Server
 * 
 * Provides a tool for visualizing Sentinel sign-in data as an interactive heatmap.
 * Accepts JSON data from Sentinel KQL queries and renders it inline in VS Code chat.
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

// Schema for heatmap cell data
const HeatmapCellSchema = z.object({
  row: z.string().describe("Row label (e.g., application name, location, user)"),
  column: z.string().describe("Column label (e.g., hour, day, date)"),
  value: z.number().describe("Numeric value for the cell (e.g., sign-in count)"),
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

// Schema for the full heatmap data input
const HeatmapDataInputSchema = z.object({
  data: z.array(HeatmapCellSchema).describe("Array of heatmap cells with row, column, and value"),
  title: z.string().optional().default("Sign-In Heatmap").describe("Title displayed above the heatmap"),
  rowLabel: z.string().optional().default("Application").describe("Label for rows (e.g., 'Application', 'Location', 'User')"),
  colLabel: z.string().optional().default("Time").describe("Label for columns (e.g., 'Hour', 'Day', 'Date')"),
  valueLabel: z.string().optional().default("Sign-ins").describe("Label for cell values (e.g., 'Sign-ins', 'Failed Attempts')"),
  colorScale: z.enum(["green-red", "blue-red", "blue-yellow"]).optional().default("green-red")
    .describe("Color scale: green-red (high=green), blue-red (high=red for threats), blue-yellow (neutral)"),
  enrichment: z.array(EnrichmentSchema).optional().describe("Optional IP enrichment data for clickable drill-down"),
});

// Output schema for structured content
const HeatmapOutputSchema = z.object({
  data: z.array(HeatmapCellSchema),
  title: z.string(),
  rowLabel: z.string(),
  colLabel: z.string(),
  valueLabel: z.string(),
  colorScale: z.string(),
  stats: z.object({
    totalCells: z.number(),
    totalValue: z.number(),
    maxValue: z.number(),
    minValue: z.number(),
    uniqueRows: z.number(),
    uniqueCols: z.number(),
  }),
  generatedAt: z.string(),
  enrichment: z.array(EnrichmentSchema).optional(),
});

function computeStats(data: z.infer<typeof HeatmapCellSchema>[]) {
  const values = data.map(d => d.value);
  const rows = new Set(data.map(d => d.row));
  const cols = new Set(data.map(d => d.column));
  
  return {
    totalCells: data.length,
    totalValue: values.reduce((a, b) => a + b, 0),
    maxValue: Math.max(...values),
    minValue: Math.min(...values),
    uniqueRows: rows.size,
    uniqueCols: cols.size,
  };
}

function formatSummary(
  data: z.infer<typeof HeatmapCellSchema>[],
  title: string,
  rowLabel: string,
  colLabel: string,
  valueLabel: string
): string {
  const stats = computeStats(data);
  return `${title}
${rowLabel}s: ${stats.uniqueRows}
${colLabel} periods: ${stats.uniqueCols}
Total ${valueLabel}: ${stats.totalValue.toLocaleString()}
Max ${valueLabel}: ${stats.maxValue.toLocaleString()}
Min ${valueLabel}: ${stats.minValue.toLocaleString()}`;
}

export function createServer(): McpServer {
  const server = new McpServer({
    name: "Sentinel Heatmap Server",
    version: "0.1.0",
  });

  const resourceUri = "ui://show-signin-heatmap/mcp-app.html";

  // Register the heatmap visualization tool
  registerAppTool(
    server,
    "show-signin-heatmap",
    {
      title: "Show Sign-In Heatmap",
      description: `Displays Sentinel sign-in data as an interactive heatmap visualization. 
Pass aggregated data from KQL queries with row (e.g., app name), column (e.g., hour), and value (e.g., count).
Supports multiple color scales for different use cases (green-red for success rates, blue-red for threat detection).`,
      inputSchema: HeatmapDataInputSchema.shape,
      outputSchema: HeatmapOutputSchema.shape,
      _meta: { ui: { resourceUri } },
    },
    async ({ data, title, rowLabel, colLabel, valueLabel, colorScale, enrichment }) => {
      const stats = computeStats(data);
      
      return {
        content: [
          { 
            type: "text", 
            text: formatSummary(data, title, rowLabel, colLabel, valueLabel) 
          }
        ],
        structuredContent: {
          data,
          title,
          rowLabel,
          colLabel,
          valueLabel,
          colorScale,
          stats,
          generatedAt: new Date().toISOString(),
          enrichment,
        },
      };
    }
  );

  // Register the HTML resource for the heatmap UI
  registerAppResource(
    server,
    resourceUri,
    resourceUri,
    { mimeType: RESOURCE_MIME_TYPE },
    async (): Promise<ReadResourceResult> => {
      const html = await fs.readFile(
        path.join(DIST_DIR, "mcp-app.html"),
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
