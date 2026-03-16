# Penetration Test Report — Remediation Roadmap

**Client:** {{client}}
**Engagement ID:** {{engagement_id}}
**Assessment Period:** {{start_date}} to {{end_date}}
**Report Date:** {{report_date}}
**Status:** {{status}}

---

## Overview

This remediation roadmap prioritizes findings by severity and provides actionable guidance for each issue. Items are grouped into priority tiers corresponding to recommended response timeframes.

## Risk Summary

| Severity | Count | Target Timeframe |
|----------|-------|------------------|
| Critical | {{critical_count}} | Immediate (24-72 hours) |
| High | {{high_count}} | Short-term (1-2 weeks) |
| Medium | {{medium_count}} | Medium-term (30 days) |
| Low | {{low_count}} | Long-term (quarterly review) |
| Informational | {{info_count}} | Best practice / advisory |

## Remediation Items

{{findings_section}}

## Verification Plan

After remediation is complete, a retest engagement should be scheduled to verify:

1. All critical and high findings have been fully remediated
2. No new vulnerabilities were introduced during remediation
3. Compensating controls are effective where direct remediation was not possible

The retest comparison tool will automatically match findings between the baseline and retest engagements, producing a delta report showing:
- **Remediated** — findings no longer present
- **Persistent** — findings still present at same severity
- **Regressed** — findings present at higher severity
- **New** — findings not present in baseline

## Tools Summary

{{tools_section}}

## Notes

- Findings marked as false positives have been excluded from this roadmap
- Remediation guidance is based on industry best practices and may need adaptation for your specific environment
- For technical details on each finding, refer to the Technical Findings report
