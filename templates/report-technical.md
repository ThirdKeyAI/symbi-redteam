# Penetration Test Report — Technical Findings

**Client:** {{client}}
**Engagement ID:** {{engagement_id}}
**Assessment Period:** {{start_date}} to {{end_date}}
**Report Date:** {{report_date}}
**Status:** {{status}}

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Findings | {{total_findings}} |
| Critical | {{critical_count}} |
| High | {{high_count}} |
| Medium | {{medium_count}} |
| Low | {{low_count}} |
| Informational | {{info_count}} |
| Tool Runs | {{total_tool_runs}} |
| Phases Completed | {{phases_completed}} |

## Tool Execution Summary

{{tools_section}}

## Detailed Findings

{{findings_section}}

## Audit Trail

All tool executions were recorded in a cryptographic audit trail with SHA-256 hash chaining. Each finding is linked to its producing tool run via the `audit_hash` field, providing tamper-evident provenance from discovery through reporting.

The complete audit log is available at: `/app/.symbiont/audit/`
Evidence artifacts are stored at: `/app/.symbiont/evidence/{{engagement_id}}/`
