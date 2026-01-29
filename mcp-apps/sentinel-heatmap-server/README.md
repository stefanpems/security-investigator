# Sentinel Sign-In Heatmap MCP Server

An MCP App for visualizing Microsoft Sentinel sign-in data as an interactive heatmap.

## Features

- **Interactive Heatmap**: Color-coded grid showing sign-in activity patterns
- **Flexible Data Input**: Accepts any aggregated data with row/column/value structure
- **Multiple Color Scales**: 
  - `green-red`: High values are green (good for activity counts)
  - `blue-red`: High values are red (good for threat/failure counts)
  - `blue-yellow`: Neutral scale
- **Dark/Light Theme**: Adapts to VS Code theme

## Usage

The heatmap accepts JSON data in this format:

```json
{
  "data": [
    {"row": "Microsoft Teams", "column": "10:00", "value": 45},
    {"row": "Microsoft Teams", "column": "11:00", "value": 62},
    {"row": "Outlook", "column": "10:00", "value": 128}
  ],
  "title": "Sign-Ins by Application (Last 24h)",
  "rowLabel": "Application",
  "colLabel": "Hour",
  "valueLabel": "Sign-ins",
  "colorScale": "green-red"
}
```

## Example KQL Query

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| summarize SigninCount = count() by 
    AppDisplayName, 
    Hour = bin(TimeGenerated, 1h)
| project 
    row = AppDisplayName,
    column = format_datetime(Hour, "HH:mm"),
    value = SigninCount
```

## Development

```bash
# Install dependencies
npm install

# Build the app
npm run build

# Run in stdio mode
npm run start:stdio
```

## MCP Client Configuration

Add to your `.vscode/mcp.json`:

```json
{
  "servers": {
    "sentinel-heatmap": {
      "command": "node",
      "args": ["<path-to>/mcp-apps/sentinel-heatmap-server/dist/main.js", "--stdio"],
      "type": "stdio"
    }
  }
}
```
