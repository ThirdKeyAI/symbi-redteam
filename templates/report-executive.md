# Penetration Test Report — Executive Summary

**Client:** {{client}}
**Engagement ID:** {{engagement_id}}
**Assessment Period:** {{start_date}} to {{end_date}}
**Report Date:** {{report_date}}
**Status:** {{status}}

---

## Objective

This penetration test was conducted to identify security vulnerabilities in the target environment and provide actionable recommendations for remediation. The assessment followed the Penetration Testing Execution Standard (PTES) methodology with automated governance ensuring all activities remained within the approved scope.

## Scope

All testing was performed against the targets defined in the Rules of Engagement (ROA). Every action was authorized by Cedar security policies and recorded in a tamper-evident audit trail.

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | {{critical_count}} |
| High | {{high_count}} |
| Medium | {{medium_count}} |
| Low | {{low_count}} |
| Informational | {{info_count}} |
| **Total** | **{{total_findings}}** |

**Phases Completed:** {{phases_completed}}
**Tool Runs Executed:** {{total_tool_runs}}

## Key Findings

{{findings_section}}

## Methodology

The assessment was conducted using a governed AI agent orchestrating the following phases:

1. **Reconnaissance** — Network discovery, port scanning, service identification
2. **Enumeration** — Directory brute forcing, SMB/SNMP enumeration, web technology fingerprinting
3. **Vulnerability Assessment** — Template-based scanning, SQL injection detection, NSE scripts
4. **Exploitation** — Credential testing, exploit execution (human-approved)
5. **Post-Exploitation** — Lateral movement, credential extraction (human-approved)

Every tool execution was gated by Cedar security policies enforcing:
- Target scope restrictions
- Risk-tiered authorization
- Rate limiting
- Mandatory human approval for high-risk operations

## Tools Utilized

{{tools_section}}

## Recommendations

1. **Immediate** — Address all critical and high severity findings within 7 days
2. **Short-term** — Remediate medium severity findings within 30 days
3. **Long-term** — Review and address low severity findings as part of regular maintenance
4. **Retest** — Schedule a follow-up engagement to verify remediation effectiveness

## Disclaimer

This report represents findings at the time of testing. New vulnerabilities may emerge after the assessment period. The findings are limited to the targets and methodologies described in the Rules of Engagement.
