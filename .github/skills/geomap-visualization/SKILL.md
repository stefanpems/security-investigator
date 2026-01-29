---
name: geomap-visualization
description: Use this skill when asked to create geographic maps, visualize attack origins on a world map, show location-based data, or display IP geolocation. Triggers on keywords like "geomap", "world map", "geographic", "attack map", "show on map", "visualize locations", "attack origins", or when analyzing data with latitude/longitude coordinates.
---

# Geomap Visualization Skill

## Purpose

Generate interactive world map visualizations from Microsoft Sentinel data using the Sentinel Geomap MCP App. Geomaps display markers on a world map with coordinates, ideal for visualizing attack origins, geographic distribution of threats, or location-based security data.

---

## 📑 TABLE OF CONTENTS

1. **[Quick Start](#quick-start)** - Minimal example to get started
2. **[MCP Tool Reference](#mcp-tool-reference)** - Parameters and schemas
3. **[Data Sources](#data-sources)** - Tables with native vs enriched geolocation
4. **[KQL Query Patterns](#kql-query-patterns)** - Ready-to-use queries by scenario
5. **[Enrichment Integration](#enrichment-integration)** - Adding threat intel drill-down
6. **[Examples](#complete-examples)** - End-to-end workflows

---

## Quick Start

### Minimal Geomap (3 Steps)

```
# 1. Query Sentinel for data with coordinates
mcp_sentinel-data_query_lake({
  "query": "W3CIISLog | where TimeGenerated > ago(7d) | where scStatus == '401' | summarize value = count(), lat = take_any(RemoteIPLatitude), lon = take_any(RemoteIPLongitude) by ip = cIP | where lat != 0 | project ip, lat, lon, value"
})

# 2. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [<query results>],
  "title": "Attack Origins (Last 7 Days)",
  "valueLabel": "Failed Logins",
  "colorScale": "blue-red"
})
```

---

## MCP Tool Reference

### Tool: `mcp_sentinel-geom_show-attack-map`

| Parameter | Required | Type | Description |
|-----------|----------|------|-------------|
| `data` | ✅ | array | Array of `{ip, lat, lon, value}` objects |
| `title` | ❌ | string | Title displayed above map (default: "Attack Origin Map") |
| `valueLabel` | ❌ | string | Label for values (default: "Attacks") |
| `colorScale` | ❌ | string | `blue-red` (threats), `green-red`, or `blue-yellow` |
| `enrichment` | ❌ | array | IP enrichment data for click-to-expand panels |

### Data Schema

```json
{
  "data": [
    {"ip": "101.36.107.228", "lat": 22.25, "lon": 114.15, "value": 44},
    {"ip": "193.142.147.209", "lat": 52.35, "lon": 4.92, "value": 13},
    {"ip": "170.64.158.196", "lat": -33.90, "lon": 151.19, "value": 9}
  ]
}
```

### Enrichment Schema (Optional)

```json
{
  "enrichment": [
    {
      "ip": "101.36.107.228",
      "city": "Hong Kong",
      "country": "HK",
      "org": "AS135377 UCLOUD INFORMATION TECHNOLOGY",
      "is_vpn": true,
      "is_proxy": false,
      "is_tor": false,
      "abuse_confidence_score": 100,
      "total_reports": 4612,
      "last_reported": "2026-01-29",
      "threat_categories": ["SSH", "Brute-Force", "Web App Attack"]
    }
  ]
}
```

---

## Data Sources

### Tables with Native Geolocation

Some Sentinel tables include lat/lon directly from Microsoft's GeoIP enrichment:

| Table | Latitude Column | Longitude Column | Country Column |
|-------|-----------------|------------------|----------------|
| **W3CIISLog** | `RemoteIPLatitude` | `RemoteIPLongitude` | `RemoteIPCountry` |
| **CommonSecurityLog** | `DeviceGeoLatitude` | `DeviceGeoLongitude` | `DeviceGeoCountry` |
| **AzureDiagnostics** | varies by source | varies by source | varies by source |
| **AzureNetworkAnalytics** | `SrcGeoLatitude` | `SrcGeoLongitude` | `SrcGeoCountry` |

**Use these when available** - no enrichment needed for coordinates.

### Tables Requiring IP Enrichment

These tables have IP addresses but **no coordinates**:

| Table | IP Column | Enrichment Required |
|-------|-----------|---------------------|
| **SigninLogs** | `IPAddress` | Yes - use `enrich_ips.py` |
| **SecurityEvent** | `IpAddress` | Yes - use `enrich_ips.py` |
| **Syslog** | extract from message | Yes - use `enrich_ips.py` |
| **DeviceNetworkEvents** | `RemoteIP` | Yes - use `enrich_ips.py` |
| **OfficeActivity** | `ClientIP` | Yes - use `enrich_ips.py` |

**Enrichment script now captures `latitude` and `longitude` from ipinfo.io.**

---

## KQL Query Patterns

### Pattern 1: Native Geolocation (W3CIISLog)

```kql
W3CIISLog
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where <filter_condition>
| summarize 
    value = count(),
    lat = take_any(RemoteIPLatitude),
    lon = take_any(RemoteIPLongitude),
    country = take_any(RemoteIPCountry)
    by ip = cIP
| where lat != 0 and lon != 0  // Filter unknown locations
| project ip, lat, lon, value
| order by value desc
```

### Pattern 2: Native Geolocation (CommonSecurityLog)

```kql
CommonSecurityLog
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where <filter_condition>
| summarize 
    value = count(),
    lat = take_any(DeviceGeoLatitude),
    lon = take_any(DeviceGeoLongitude)
    by ip = SourceIP
| where lat != 0 and lon != 0
| project ip, lat, lon, value
| order by value desc
```

### Pattern 3: Enrichment Required (Extract IPs Only)

```kql
<Table>
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where <filter_condition>
| summarize value = count() by ip = <IP_column>
| order by value desc
| take 100
```

Then run `enrich_ips.py` to get lat/lon.

---

## Scenario-Specific KQL Queries

### Scenario: W3CIISLog - Failed Logins (Native Geo)

```kql
W3CIISLog
| where TimeGenerated > ago(90d)
| where Computer startswith "<honeypot_name>"
| where scStatus == "401"  // Failed auth
| where cIP != "127.0.0.1"
| summarize 
    value = count(),
    lat = take_any(RemoteIPLatitude),
    lon = take_any(RemoteIPLongitude),
    country = take_any(RemoteIPCountry)
    by ip = cIP
| where lat != 0 and lon != 0
| project ip, lat, lon, value
| order by value desc
```

### Scenario: W3CIISLog - Web Attacks (Native Geo)

```kql
W3CIISLog
| where TimeGenerated > ago(30d)
| where tolong(scStatus) >= 400
| where csUriStem has_any ("'", "union", "select", "script", "../", "cmd.exe")
| where cIP != "127.0.0.1"
| summarize 
    value = count(),
    lat = take_any(RemoteIPLatitude),
    lon = take_any(RemoteIPLongitude)
    by ip = cIP
| where lat != 0
| project ip, lat, lon, value
| order by value desc
| take 100
```

### Scenario: CommonSecurityLog - Firewall Blocks (Native Geo)

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceAction == "Deny" or Activity has "blocked"
| summarize 
    value = count(),
    lat = take_any(DeviceGeoLatitude),
    lon = take_any(DeviceGeoLongitude)
    by ip = SourceIP
| where lat != 0 and lon != 0
| project ip, lat, lon, value
| order by value desc
| take 100
```

### Scenario: SigninLogs - Failed Sign-ins (Requires Enrichment)

**Step 1: Query IPs and values**
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0  // Failed
| summarize value = count() by ip = IPAddress
| order by value desc
| take 50
```

**Step 2: Enrich IPs**
```powershell
python enrich_ips.py <ip1> <ip2> <ip3> ...
```

**Step 3: Build map data from enrichment JSON (includes lat/lon)**

### Scenario: SecurityEvent - RDP Brute Force (Requires Enrichment)

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| where LogonType == 10  // RDP
| where IpAddress != "-" and IpAddress != "127.0.0.1"
| summarize value = count() by ip = IpAddress
| order by value desc
| take 50
```

Then enrich to get coordinates.

### Scenario: DeviceNetworkEvents - Inbound Attacks (Requires Enrichment)

```kql
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where DeviceName =~ "<device_name>"
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| where LocalPort in (3389, 22, 445, 80, 443)
| where RemoteIP !startswith "192.168." and RemoteIP !startswith "10."
| summarize value = count() by ip = RemoteIP
| order by value desc
| take 50
```

---

## Enrichment Integration

### When Coordinates Are Not in Sentinel

For tables without native geo fields, use the enrichment script:

**Step 1:** Run your KQL query to get IPs and values

**Step 2:** Enrich IPs:
```powershell
python enrich_ips.py 203.0.113.42 198.51.100.10 192.0.2.1
# Or from file:
python enrich_ips.py --file temp/attack_ips.json
```

**Step 3:** Load enrichment JSON and build map data:
```python
import json

# Load enrichment (now includes latitude/longitude from ipinfo.io)
with open('temp/ip_enrichment_<timestamp>.json', 'r') as f:
    enrichment = json.load(f)

# Build map data
map_data = []
enrichment_out = []

for e in enrichment:
    ip = e['ip']
    lat = e.get('latitude')
    lon = e.get('longitude')
    
    if lat is None or lon is None:
        continue  # Skip IPs without coordinates
    
    # Get value from your KQL results (create a lookup dict)
    value = attack_counts.get(ip, 1)
    
    map_data.append({
        'ip': ip,
        'lat': lat,
        'lon': lon,
        'value': value
    })
    
    # Build enrichment for drill-down
    threat_cats = []
    for c in e.get('recent_comments', [])[:5]:
        threat_cats.extend(c.get('categories', []))
    
    enrichment_out.append({
        'ip': ip,
        'city': e.get('city', 'Unknown'),
        'country': e.get('country', '??'),
        'org': e.get('org', 'Unknown'),
        'is_vpn': e.get('is_vpn') or e.get('vpnapi_security_vpn', False),
        'abuse_confidence_score': e.get('abuse_confidence_score', 0),
        'total_reports': e.get('total_reports', 0),
        'last_reported': e.get('recent_comments', [{}])[0].get('date', '')[:10] if e.get('recent_comments') else '',
        'threat_categories': list(set(threat_cats))[:5]
    })
```

### Interactive Features with Enrichment

When enrichment is provided:
- **Click any marker** → Opens threat intel panel showing:
  - 📍 Location (city, country)
  - 🏢 Organization/ISP
  - 🏷️ VPN/Proxy/Tor badges
  - 📊 AbuseIPDB confidence meter
  - 📈 Total reports count
  - 🔴 Threat category tags

---

## Color Scale Guide

| Scale | Low Value | High Value | Best For |
|-------|-----------|------------|----------|
| `blue-red` | Blue | Red | **Threats** (attacks, failures) - DEFAULT |
| `green-red` | Teal | Green | Positive activity (benign traffic) |
| `blue-yellow` | Blue | Yellow | Neutral data distributions |

**For threat/attack maps, always use `blue-red`.**

---

## Complete Examples

### Example 1: 90-Day Honeypot Attack Map (Native Geo)

```
# 1. Query with native lat/lon from W3CIISLog
mcp_sentinel-data_query_lake({
  "query": "W3CIISLog | where TimeGenerated > ago(90d) | where Computer startswith '<HONEYPOT_SERVER>' | where scStatus == '401' | summarize value = count(), lat = take_any(RemoteIPLatitude), lon = take_any(RemoteIPLongitude), country = take_any(RemoteIPCountry) by ip = cIP | where lat != 0 and lon != 0 | project ip, lat, lon, value | order by value desc"
})

# 2. Enrich top IPs for threat intel drill-down
python enrich_ips.py 101.36.107.228 193.142.147.209 80.190.82.185

# 3. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [
    {"ip": "101.36.107.228", "lat": 22.25, "lon": 114.15, "value": 44},
    {"ip": "80.190.82.185", "lat": 50.97, "lon": 6.83, "value": 44},
    {"ip": "193.142.147.209", "lat": 52.35, "lon": 4.92, "value": 13},
    {"ip": "170.64.158.196", "lat": -33.9, "lon": 151.19, "value": 9}
  ],
  "title": "Honeypot Attack Origins - 90 Day Analysis",
  "valueLabel": "Failed Logins",
  "colorScale": "blue-red",
  "enrichment": [
    {"ip": "101.36.107.228", "city": "Hong Kong", "country": "HK", "org": "AS135377 UCLOUD", "is_vpn": true, "abuse_confidence_score": 100, "total_reports": 4612, "threat_categories": ["SSH", "Brute-Force"]},
    {"ip": "193.142.147.209", "city": "Amsterdam", "country": "NL", "org": "AS213438 ColocaTel", "is_vpn": true, "abuse_confidence_score": 100, "total_reports": 30973, "threat_categories": ["Web App Attack", "Hacking"]}
  ]
})
```

### Example 2: SigninLogs Attack Map (Enrichment Required)

```
# 1. Query IPs with failed sign-ins
mcp_sentinel-data_query_lake({
  "query": "SigninLogs | where TimeGenerated > ago(7d) | where ResultType != 0 | summarize value = count() by ip = IPAddress | order by value desc | take 50"
})

# 2. Enrich all IPs (script now captures lat/lon)
python enrich_ips.py <ip1> <ip2> ...

# 3. Load enrichment JSON and build map data
# (See Python code in Enrichment Integration section)

# 4. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [<map_data from enrichment>],
  "title": "Failed Sign-In Origins (Last 7 Days)",
  "valueLabel": "Failed Attempts",
  "colorScale": "blue-red",
  "enrichment": [<enrichment_out>]
})
```

### Example 3: Firewall Blocks (Native Geo)

```
# 1. Query blocked traffic with geo
mcp_sentinel-data_query_lake({
  "query": "CommonSecurityLog | where TimeGenerated > ago(24h) | where DeviceAction == 'Deny' | summarize value = count(), lat = take_any(DeviceGeoLatitude), lon = take_any(DeviceGeoLongitude) by ip = SourceIP | where lat != 0 | project ip, lat, lon, value | order by value desc | take 100"
})

# 2. Display geomap
mcp_sentinel-geom_show-attack-map({
  "data": [<query results>],
  "title": "Blocked Traffic Origins (Last 24h)",
  "valueLabel": "Blocked Connections",
  "colorScale": "blue-red"
})
```

---

## Technical Notes

- **Projection:** Robinson projection for accurate world map display
- **Map Source:** SimpleMaps.com world SVG (MIT license)
- **Bundle Size:** ~650 KB (includes embedded world map)
- **CSP Compliance:** No external resources - all assets embedded inline
- **Coordinate System:** Standard WGS84 (latitude: -90 to 90, longitude: -180 to 180)

---

## When to Use Geomaps

✅ **Good Use Cases:**
- Attack origin visualization (honeypots, firewalls)
- Geographic threat distribution
- Anomalous sign-in locations
- VPN/anonymization analysis across regions
- Executive briefings on global threats

❌ **Skip Geomaps When:**
- Fewer than 3 unique locations (too sparse)
- All IPs from same region (use heatmap instead)
- Time-based patterns needed (use heatmap)
- No geographic data available and enrichment not feasible

---

*Last Updated: January 29, 2026*
