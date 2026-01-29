# Sentinel Geo Map MCP Server

An MCP App for visualizing Microsoft Sentinel security data as an interactive world map with attack origin markers.

## Features

- **Interactive World Map**: Robinson projection world map with clickable markers
- **Embedded SVG**: Uses SimpleMaps.com SVG (MIT license) - no external tile servers required
- **CSP Compliant**: Works within VS Code's strict Content Security Policy
- **Threat Intel Drill-Down**: Click markers to view enrichment data (VPN, abuse scores, threat categories)
- **Multiple Color Scales**: 
  - `blue-red`: High values are red (default - good for threats)
  - `green-red`: High values are green (good for benign activity)
  - `blue-yellow`: Neutral scale
- **Dark Theme**: Styled to match VS Code dark theme

## Usage

The geo map accepts JSON data in this format:

```json
{
  "data": [
    {"ip": "101.36.107.228", "lat": 22.25, "lon": 114.15, "value": 44},
    {"ip": "193.142.147.209", "lat": 52.35, "lon": 4.92, "value": 13},
    {"ip": "170.64.158.196", "lat": -33.90, "lon": 151.19, "value": 9}
  ],
  "title": "Honeypot Attack Origins - 90 Day Analysis",
  "valueLabel": "Failed Logins",
  "colorScale": "blue-red",
  "enrichment": [
    {
      "ip": "101.36.107.228",
      "city": "Hong Kong",
      "country": "HK",
      "org": "AS135377 UCLOUD INFORMATION TECHNOLOGY",
      "is_vpn": true,
      "abuse_confidence_score": 100,
      "total_reports": 4612,
      "threat_categories": ["SSH", "Brute-Force", "Web App Attack"]
    }
  ]
}
```

## Data Sources

### Tables with Native Geolocation

Some Sentinel tables include lat/lon directly from Microsoft's GeoIP enrichment:

| Table | Latitude Column | Longitude Column | Country Column |
|-------|-----------------|------------------|----------------|
| W3CIISLog | `RemoteIPLatitude` | `RemoteIPLongitude` | `RemoteIPCountry` |
| CommonSecurityLog | `DeviceGeoLatitude` | `DeviceGeoLongitude` | `DeviceGeoCountry` |
| AzureDiagnostics | varies by source | varies by source | varies by source |

### Tables Requiring IP Enrichment

Tables like `SigninLogs`, `SecurityEvent`, `Syslog` have IP addresses but no coordinates. Use the enrichment script to add lat/lon:

```bash
python enrich_ips.py 203.0.113.42 198.51.100.10
```

The script now captures `latitude` and `longitude` fields from ipinfo.io.

## Example KQL Queries

### W3CIISLog - Failed Logins with Native Geo

```kql
W3CIISLog
| where TimeGenerated > ago(90d)
| where Computer startswith "honeypot-server"
| where scStatus == "401"
| summarize 
    FailedLogins = count(),
    Lat = take_any(RemoteIPLatitude),
    Lon = take_any(RemoteIPLongitude),
    Country = take_any(RemoteIPCountry)
    by cIP
| where Lat != 0 and Lon != 0  // Filter out unknown locations
| project ip = cIP, lat = Lat, lon = Lon, value = FailedLogins
| order by value desc
```

### CommonSecurityLog - Attack Origins

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where Activity has "attack" or Activity has "blocked"
| summarize 
    AttackCount = count(),
    Lat = take_any(DeviceGeoLatitude),
    Lon = take_any(DeviceGeoLongitude)
    by SourceIP
| where Lat != 0 and Lon != 0
| project ip = SourceIP, lat = Lat, lon = Lon, value = AttackCount
```

## Tool Parameters

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `data` | ✅ | array | Array of `{ip, lat, lon, value}` objects |
| `title` | ❌ | string | Map title (default: "Attack Origin Map") |
| `valueLabel` | ❌ | string | Label for values (default: "Attacks") |
| `colorScale` | ❌ | string | Color scheme: `blue-red`, `green-red`, `blue-yellow` |
| `enrichment` | ❌ | array | IP enrichment data for drill-down panels |

## Enrichment Schema

Providing enrichment enables click-to-expand threat intel panels:

```json
{
  "ip": "192.0.2.1",
  "city": "Amsterdam",
  "country": "NL",
  "org": "AS206264 Amarutu Technology Ltd",
  "is_vpn": true,
  "is_proxy": false,
  "is_tor": false,
  "abuse_confidence_score": 100,
  "total_reports": 3429,
  "last_reported": "2026-01-29",
  "threat_categories": ["Web App Attack", "Brute-Force", "Port Scan"]
}
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
    "sentinel-geomap": {
      "command": "node",
      "args": ["<path-to>/mcp-apps/sentinel-geomap-server/dist/main.js", "--stdio"],
      "type": "stdio"
    }
  }
}
```

## Technical Notes

- **Projection**: Robinson projection for accurate world map display
- **Map Source**: SimpleMaps.com world SVG (MIT license)
- **Bundle Size**: ~650 KB (includes embedded world map)
- **CSP Compliance**: No external resources - all assets embedded inline
