# GitHub Copilot - Security Investigation Integration

This workspace contains a security investigation automation system. GitHub Copilot can help you run investigations using natural language.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Available Skills](#available-skills)** - Specialized investigation workflows
3. **[Universal Patterns](#universal-patterns)** - Date ranges, time tracking, token management
4. **[Follow-Up Analysis](#-critical-follow-up-analysis-workflow-mandatory)** - Working with existing data
5. **[CA Policy Analysis](#appendix-conditional-access-policy-investigation-workflow)** - Conditional Access troubleshooting
6. **[Ad-Hoc Queries](#appendix-ad-hoc-query-examples)** - Quick reference patterns
7. **[Troubleshooting](#troubleshooting-guide)** - Common issues and solutions

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**🤖 SPECIALIZED SKILLS DETECTION:**

**BEFORE starting any investigation, detect if user request requires a specialized skill:**

| Keywords in Request | Action Required |
|---------------------|-----------------|
| **"investigate user"**, "security investigation", "check user activity", UPN/email with investigation context | Use the **user-investigation** skill at `.github/skills/user-investigation/SKILL.md` |
| **"honeypot"**, "attack analysis", "threat actor" | Use the **honeypot-investigation** skill at `.github/skills/honeypot-investigation/SKILL.md` |
| **"write KQL"**, "create KQL query", "help with KQL", "query [table]", "KQL for [scenario]" | Use the **kql-query-authoring** skill at `.github/skills/kql-query-authoring/SKILL.md` |
| **"trace authentication"**, "trace back to interactive MFA", "SessionId analysis", "token reuse", "geographic anomaly", "impossible travel" | Use the **authentication-tracing** skill at `.github/skills/authentication-tracing/SKILL.md` |
| **Future skills** | Check `.github/skills/` folder with `list_dir` to discover available specialized workflows |

**Detection Pattern:**
1. Parse user request for specialized keywords
2. If match found: Read the appropriate SKILL.md file from `.github/skills/<skill-name>/SKILL.md`
3. Follow skill-specific workflow (inherits universal patterns from this file)

---

## Available Skills

| Skill | Description | Trigger Keywords |
|-------|-------------|------------------|
| **user-investigation** | Azure AD user security analysis: sign-ins, anomalies, MFA, devices, audit logs, incidents, Identity Protection, HTML reports | "investigate user", "security investigation", "check user activity", UPN/email |
| **honeypot-investigation** | Honeypot security analysis: attack patterns, threat intel, vulnerabilities, executive reports | "honeypot", "attack analysis", "threat actor" |
| **kql-query-authoring** | KQL query creation using schema validation, community examples, Microsoft Learn | "write KQL", "create KQL query", "help with KQL", "query [table]" |
| **authentication-tracing** | Azure AD authentication chain forensics: SessionId analysis, token reuse vs interactive MFA, geographic anomaly investigation, risk assessment | "trace authentication", "trace back to interactive MFA", "SessionId analysis", "token reuse", "geographic anomaly" |

**Skill files location:** `.github/skills/<skill-name>/SKILL.md`

---

## Universal Patterns

**These patterns apply to ALL skills and ad-hoc queries:**

**Why this matters:**
- Sample queries include proper field handling (`Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'`)
- They avoid errors on dynamic fields (LocationDetails, ModifiedProperties, DeviceDetail)
- They're production-validated

**Example: User asks "What's that password reset about?" → Go to Sample Queries → Use Query #4**

---

## 🔄 CRITICAL: Follow-Up Analysis Workflow (MANDATORY)

**⚠️ BEFORE answering ANY follow-up question, you MUST:**
1. ✅ Check if investigation JSON exists for that user/date range
2. ✅ **Search copilot-instructions.md for relevant guidance** (use grep_search with topic keyword)
3. ✅ **Query Sentinel/Graph if you need addtional data** ONLY query Sentinel/Graph if enriched data AND instructions are insufficient
4. ✅ Search `ip_enrichment` json for relevant IP's if needed before coming to conclusions (contains VPN, ISP, abuse scores, threat intel)


**Common follow-up patterns that REQUIRE using enriched JSON:**
- "Trace authentication for [IP/location]" → Read `ip_enrichment` array + `signin_ip_counts`
- "Is that a VPN?" → Read `ip_enrichment` array, find IP, check `is_vpn` field
- "What's the risk level?" → Read `ip_enrichment` array, check `risk_level` + `abuse_confidence_score`
- "Tell me about [IP address]" → Read `ip_enrichment` array, filter by `ip` field (e.g., `"ip": "203.0.113.42"`)
- "Show me authentication details" → Read `ip_enrichment` array, check `last_auth_result_detail` field
- "Was that IP flagged by threat intel?" → Read `ip_enrichment` array, check `threat_description` field (non-empty = match)

**DO NOT re-query threat intel or sign-in data if it's already in the JSON file!**

**How to read IP enrichment data:**
1. Locate investigation JSON: `temp/investigation_<upn_prefix>_<timestamp>.json`
2. Read file and parse JSON structure
3. Navigate to `ip_enrichment` array (near end of file, after `risk_detections`/`risky_signins`)
4. Find IP entry: `ip_enrichment` is an array of objects - filter by `"ip": "<target_ip>"`
5. Extract relevant fields: `is_vpn`, `abuse_confidence_score`, `threat_description`, `last_auth_result_detail`, etc.

**How to find the investigation JSON:**
- Pattern: `temp/investigation_<upn_prefix>_<timestamp>.json`
- Most recent file for user is usually the one to analyze
- Use `file_search` or `list_dir` to locate existing investigations

---

## Integration with MCP Servers

The investigation system integrates with these MCP servers (which Copilot has access to):

### Microsoft Sentinel MCP
- **mcp_sentinel-mcp-2_query_lake**: Execute KQL queries
- **mcp_sentinel-mcp-2_search_tables**: Discover table schemas
- **mcp_sentinel-mcp-2_list_sentinel_workspaces**: List available workspaces

### Microsoft Graph MCP
- **mcp_microsoft_mcp_microsoft_graph_suggest_queries**: Find Graph API endpoints
- **mcp_microsoft_mcp_microsoft_graph_get**: Execute Graph API calls
- **mcp_microsoft_mcp_microsoft_graph_list_properties**: Explore entity schemas

## Configuration

Configuration is stored in `config.json`:
```json
{
  "sentinel_workspace_id": "<YOUR_WORKSPACE_ID>",
  "tenant_id": "your-tenant-id-here",
  "ipinfo_token": null,
  "output_dir": "reports"
}
```

---

## APPENDIX: Conditional Access Policy Investigation Workflow

### Critical Investigation Rules

When investigating sign-in failures (error codes 53000, 50074) with CA policy correlation:

**⚠️ MANDATORY STEPS - DO NOT SKIP:**

1. **Query ALL CA policy changes in chronological order** (±2 days from failure time)
2. **Parse policy state transitions** from the JSON (enabled → disabled → report-only)
3. **Compare failure timeline with policy change timeline**
4. **Verify logical consistency**: Ask "does this make sense?"

### Common Error Codes

| Error Code | Description | Typical Cause |
|------------|-------------|---------------|
| **53000** | Device not compliant | Device not enrolled in Intune or failing compliance checks |
| **50074** | Strong authentication required | MFA not satisfied |
| **50074** | User must enroll in MFA | MFA not configured for user |
| **530032** | Blocked by CA policy | Generic CA policy block |
| **65001** | User consent required | Application consent needed |

### CA Policy State Meanings

| State | What It Means | Security Impact |
|-------|---------------|----------------|
| **enabled** | Policy actively enforcing | Blocks non-compliant access (intended behavior) |
| **disabled** | Policy not enforcing | **Security control bypassed** - all access allowed |
| **enabledForReportingButNotEnforced** | Report-only mode | Logs violations but **doesn't block** - defeats purpose |

### Investigation Workflow Pattern

**Step 1: Identify Sign-In Failures**
```kql
// Get failures with CA context
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(<START>) .. datetime(<END>))
| where UserPrincipalName =~ '<UPN>'
| where ResultType != '0'
| where AppDisplayName has '<APPLICATION>'  // e.g., "Visual Studio Code"
| project TimeGenerated, IPAddress, Location, ResultType, ResultDescription, 
    ConditionalAccessStatus, UserAgent
| order by TimeGenerated asc
```

**Step 2: Query ALL CA Policy Changes in Timeframe**
```kql
let failure_time = datetime(<FIRST_FAILURE_TIME>);
let start = failure_time - 2d;
let end = failure_time + 2d;
AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName has_any ("Conditional Access", "policy")
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| extend InitiatorUPN = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| extend InitiatorIPAddress = tostring(parse_json(InitiatedBy).user.ipAddress)
| extend TargetName = tostring(parse_json(TargetResources)[0].displayName)
| project TimeGenerated, OperationName, Result, InitiatorUPN, InitiatorIPAddress, 
    TargetName, CorrelationId
| order by TimeGenerated asc  // CRITICAL: Chronological order
```

**Step 3: Parse Policy State Changes**
```kql
// For each CorrelationId from Step 2, get detailed changes
AuditLogs
| where CorrelationId == "<CORRELATION_ID>"
| extend ModifiedProperties = parse_json(TargetResources)[0].modifiedProperties
| mv-expand ModifiedProperties
| extend PropertyName = tostring(ModifiedProperties.displayName)
| extend OldValue = tostring(ModifiedProperties.oldValue)
| extend NewValue = tostring(ModifiedProperties.newValue)
| project TimeGenerated, PropertyName, OldValue, NewValue
```

**Step 4: Extract Policy State from JSON**
- Parse `OldValue` and `NewValue` JSON for `"state":"<value>"`
- Build timeline: `enabled` → `disabled` → `enabledForReportingButNotEnforced`

**Step 5: Security Assessment**

Compare timelines and assess intent:

| Pattern | Interpretation | Risk Level |
|---------|----------------|------------|
| **Failures → Policy Disabled** | User bypassed security control to unblock self | **HIGH** - Privilege abuse |
| **Failures → Policy Changed to Report-Only** | User weakened security control | **MEDIUM-HIGH** - Partial bypass |
| **Policy Disabled → Failures Continue** | Cached tokens (5-15 min propagation delay) | **INFO** - Expected behavior |
| **Policy Changed → No More Failures** | Policy change resolved issue | **Context-dependent** - May be legitimate troubleshooting |

### Real-World Example Analysis

**Scenario:** User blocked by device compliance policy, then modifies policy

**Timeline:**
- 19:05 - User blocked (error 53000: device not compliant)
- 19:09 - User changes policy: `enabled` → `disabled`
- 19:09 - User changes policy again: `disabled` → `enabledForReportingButNotEnforced`
- 19:12 - User still blocked (cached token)
- 19:14 - User access succeeds (policy propagated)

**Analysis:**
1. ✅ Policy was correctly blocking non-compliant device
2. 🚨 User disabled security control to bypass block
3. ⚠️ User partially reversed by enabling report-only (shows some awareness)
4. ❌ Report-only mode still defeats the purpose (doesn't block)

**Assessment:**
- **Risk Level:** MEDIUM-HIGH
- **Finding:** Self-service security bypass using privileged role
- **Root Cause:** User's device is non-compliant (not enrolled/failing compliance)
- **Recommendation:** 
  - Investigate why device is non-compliant
  - Implement approval workflow for CA policy changes
  - Alert on policy state changes (enabled → disabled/report-only)
  - Review if user should have permission to modify CA policies

### Critical Mistakes to Avoid

❌ **DON'T:**
- Query only ONE policy change event (you'll miss the sequence)
- Read policy changes in reverse chronological order (confuses cause/effect)
- Assume policy was already disabled without checking the starting state
- Skip verifying "does this make logical sense?" (disabled policies can't block users)

✅ **DO:**
- Query ALL policy changes in the timeframe
- Order chronologically (oldest first) to see the sequence
- Parse the full JSON to extract policy state transitions
- Cross-check: If user was blocked, policy must have been enabled at that time
- Ask: "Why would user disable this policy?" (Usually to bypass a legitimate block)

### Security Recommendations

**When CA Policy Changes Are Detected:**

1. **Determine Legitimacy:**
   - Was the policy change authorized?
   - Was there a valid business reason?
   - Did the user have approval to make this change?

2. **Assess Impact:**
   - How many users affected by policy change?
   - What applications/resources are now unprotected?
   - How long was the policy disabled/weakened?

3. **Remediation Actions:**
   - Restore policy to `enabled` state if change was unauthorized
   - Investigate root cause (why was user blocked?)
   - Fix underlying issue (device compliance, MFA enrollment, etc.)
   - Review who has permission to modify CA policies
   - Implement approval workflows for policy changes
   - Alert on future CA policy modifications

4. **Long-Term Improvements:**
   - Use PIM for Security Administrator role (require approval)
   - Implement CA policy change alerts
   - Require multi-admin approval for policy state changes
   - Document approved procedures for policy troubleshooting

---

## APPENDIX: Ad-Hoc Query Examples

### Ad-Hoc IP Enrichment Utility

For quick IP enrichment during investigation follow-ups, use the `enrich_ips.py` utility:

```powershell
# Enrich specific IPs from anomaly analysis
python enrich_ips.py 203.0.113.42 198.51.100.10 192.0.2.1

# Enrich all unenriched IPs from an investigation file
python enrich_ips.py --file temp/investigation_user_20251130.json
```

**Features:** Enriches IPs using ipinfo.io, vpnapi.io, and AbuseIPDB. Detects VPN, proxy, Tor, hosting, and abuse scores. Exports results to JSON.

**When to use:** Follow-up analysis, spot-checking suspicious IPs, completing partial investigations. **DO NOT use in main investigation workflow** (IP enrichment is already built into report generation).

---

### Best Practices for AuditLogs Queries

**CRITICAL: Use broad, simple filters for OperationName searches**

When searching AuditLogs for specific operations (password resets, role changes, policy modifications, etc.):

**❌ DON'T use overly specific filters:**
```kql
| where OperationName has_any ("password", "reset")  // May miss operations
| where OperationName == "Reset user password"       // Too restrictive - misses variations
```

**✅ DO use broad keyword matching:**
```kql
| where OperationName has "password"  // Catches all password-related operations
| where OperationName has "role"      // Catches all role-related operations
| where OperationName has "policy"    // Catches all policy-related operations
```

**Why this matters:**
- OperationName values vary: "Reset user password", "Change user password", "Self-service password reset", "Update password"
- `has_any()` requires exact word matches and can be unpredictable
- Simple `has "keyword"` is more reliable for exploratory queries
- You can always filter results further in subsequent `summarize` or `where` clauses

**Example - Finding password operations:**
```kql
AuditLogs
| where TimeGenerated between (start .. end)
| where OperationName has "password"  // Broad search
| where tostring(InitiatedBy) has '<UPN>' or tostring(TargetResources) has '<UPN>'
| summarize Count = count() by OperationName  // Then see what operations exist
| order by Count desc
```

**Then refine if needed:**
```kql
// After seeing results, target specific operation if necessary
| where OperationName == "Reset user password"
```

**Field Matching Best Practices:**
- **Always use `tostring()` for dynamic fields:** `tostring(InitiatedBy)`, `tostring(TargetResources)`
- **Use `has` for substring matching:** `tostring(InitiatedBy) has '<UPN>'`
- **Use `=~` for exact case-insensitive match:** `Identity =~ '<UPN>'`
- **Avoid direct field access on complex JSON:** Parse first with `parse_json()` then extract

---

### Enumerating User Permissions and Roles

When asked to check permissions or roles for a user account, **ALWAYS query BOTH**:

1. **Permanent Role Assignments** (active roles)
2. **PIM-Eligible Roles** (roles that can be activated on-demand)

**Step 1: Get User Object ID**
```
/v1.0/users/<UPN>?$select=id
```

**Step 2: Get Permanent Role Assignments**
```
/v1.0/roleManagement/directory/roleAssignments?$select=principalId&$filter=principalId eq '<USER_ID>'&$expand=roleDefinition($select=templateId,displayName,description)
```

**Step 3: Get PIM-Eligible Roles**
```
/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$select=memberType,startDateTime,endDateTime&$filter=principalId eq '<USER_ID>'&$expand=principal($select=id),roleDefinition($select=id,displayName,description)
```

**Step 4: Get Active PIM Role Assignments (time-bounded)**
```
/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=assignmentType,memberType,startDateTime,endDateTime&$filter=principalId eq '<USER_ID>' and startDateTime le <CURRENT_DATETIME> and endDateTime ge <CURRENT_DATETIME>&$expand=principal($select=id),roleDefinition($select=id,displayName,description)
```

**Example Output Format:**
```
Total Role Inventory for <USER>:

Permanent Active Roles (X):
1. Global Administrator
2. Security Administrator
...

PIM-Eligible Roles (Y):
1. Exchange Administrator (Eligible since: <date>, Expiration: <date or ∞>)
2. Intune Administrator (Eligible since: <date>, Expiration: <date or ∞>)
...

Active PIM Role Assignments (Z):
1. [Role Name] (Activated: <start>, Expires: <end>, Assignment Type: <type>)
...
```

**Security Analysis Guidance:**
- Flag if high-privilege roles (Global Admin, Security Admin, Application Admin) are **permanently assigned** instead of PIM-eligible
- Recommend converting permanent privileged roles to PIM-eligible with approval workflows
- Note if PIM eligibilities have no expiration (should be reviewed periodically)

---

## Output

The investigation generates:
- **JSON data file**: Raw investigation results
- **HTML report**: Professional, browser-ready report with:
  - Executive summary
  - Key metrics dashboard
  - Anomaly findings
  - IP intelligence cards
  - User profile & MFA status
  - Device inventory
  - Audit log timeline
  - Security alerts table
  - Risk assessment
  - Prioritized recommendations
  - Investigation conclusion

**Report Theme:**
- **Default**: Dark theme with Microsoft brand colors
  - Background: Dark gray gradients (#1a1a1a → #2d2d2d)
  - Primary accent: Microsoft blue (#00a1f1, #0078d4)
  - Highlights: Microsoft orange (#f65314), gold (#ffbb00), green (#7cbb00)
  - High contrast text for accessibility (#e0e0e0 on dark backgrounds)
- **Color Palette**:
  - Orange: #f65314 (critical alerts)
  - Gold: #ffbb00 (high priority)
  - Blue: #00a1f1 (medium/info)
  - Green: #7cbb00 (low/success)
  - Gray: #737373 (neutral elements)

## Example Workflow

User says: **"Investigate user@domain.com for suspicious activity in the last 7 days"**

Copilot should:
1. **Phase 1:** Get user Object ID from Microsoft Graph
2. **Phase 2:** Run all Sentinel and Graph queries in parallel batches
3. **Phase 2c:** Extract IPs and run threat intelligence query
4. **Phase 2d:** Create single JSON file with all results in temp/
5. **Phase 3:** Run `generate_report_from_json.py` script with JSON file path
6. Show the user the report path and provide brief summary

See "OPTIMIZED PARALLEL EXECUTION PATTERN" section above for detailed workflow.

## Error Handling

If the investigation encounters issues:
- Missing configuration: Falls back to defaults
- MCP query failures: Logs warnings, continues with available data
- IP enrichment failures: Returns "Error" status, continues investigation
- Missing user data: Shows "Unknown" in report, continues

The investigation is designed to be resilient and complete successfully even with partial data.

## Troubleshooting Guide

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Missing `department` or `officeLocation` in Graph API response** | Use `"Unknown"` as default value in JSON |
| **No anomalies found in Sentinel query** | Export empty array: `"anomalies": []` |
| **Graph API returns 404 for user** | Verify UPN is correct; check if user exists with different UPN |
| **Sentinel query timeout** | Reduce date range or add `| take 5` to limit results |
| **Missing `trustType` in device query** | Use default: `"trustType": "Workplace"` |
| **Null `approximateLastSignInDateTime`** | Use default: `"approximateLastSignInDateTime": "2025-01-01T00:00:00Z"` |
| **Report generation fails** | Check JSON file has ALL required fields; validate JSON syntax |
| **KQL syntax error** | Use EXACT query patterns from Sample KQL Queries section |
| **SemanticError: Failed to resolve column** | Field doesn't exist in table schema - remove it or check Sample KQL Queries for correct field names |
| **DeviceDetail, LocationDetails, ModifiedProperties errors** | These are dynamic fields - use `| take 1` to see raw structure, then parse with `parse_json()` or remove from query |
| **No results from SecurityIncident query** | Ensure you're using BOTH `targetUPN` and `targetUserId` variables |
| **Risky sign-ins query fails** | Must use `/beta` endpoint, not `/v1.0` |

### Required Field Defaults

If Graph API returns null for these fields, use these defaults:

```json
{
  "department": "Unknown",
  "officeLocation": "Unknown",
  "trustType": "Workplace",
  "approximateLastSignInDateTime": "2025-01-01T00:00:00Z"
}
```

### Empty Result Handling

If a Sentinel query returns no results, include empty arrays:

```json
{
  "anomalies": [],
  "signin_apps": [],
  "signin_locations": [],
  "signin_failures": [],
  "audit_events": [],
  "office_events": [],
  "dlp_events": [],
  "incidents": [],
  "risk_detections": [],
  "risky_signins": [],
  "threat_intel_ips": []
}
```

## Security Notes

- All reports are marked CONFIDENTIAL
- Reports contain sensitive user information
- Store reports securely
- Follow organizational data classification policies
- Investigation actions are logged for audit trail
