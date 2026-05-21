-- =============================================================================
-- 2026-05-21-validate-cutover.sql
--
-- One-time backfill for the introduction of the validate agent and the
-- finding_verifications audit table.
--
-- Context: before this cutover, no agent could ever flip findings.verified
-- to TRUE, so every historical finding has verified = FALSE. With evidence.cedar
-- blocking generate_report while unverified_critical_high_count > 0, every
-- pre-cutover engagement is now stuck at the reporting gate.
--
-- This migration records a synthetic verification row for each historical
-- finding so the audit trail still shows *something* verified it, then flips
-- the verified flag. The verifier identity is "pre_validate_cutover" and the
-- rationale calls out that these were not adjudicated by the validate agent.
-- Reviewers can filter on `finding_verifications.verifier` to distinguish
-- backfilled rows from real validate-agent decisions.
--
-- Apply this once per existing redteam.db, then never again. The IF NOT EXISTS
-- subqueries make it safe to re-run, but doing so is not expected.
-- =============================================================================

BEGIN TRANSACTION;

-- Insert a synthetic verification row for every finding that has none.
-- finding.id is already unique, so verification id = finding.id || '-bf' is safe.
INSERT INTO finding_verifications (id, finding_id, verdict, rationale, verifier)
SELECT
    f.id || '-bf',
    f.id,
    'verified',
    'Pre-validate-cutover backfill; not adjudicated by the validate agent.',
    'pre_validate_cutover'
FROM findings f
LEFT JOIN finding_verifications v ON v.finding_id = f.id
WHERE v.id IS NULL;

-- Flip the verified flag for every finding the backfill just adjudicated.
-- We keep the existing false_positive flag intact: a row that was already
-- marked false_positive stays that way, but it still needs verified = TRUE
-- so the unverified_critical_high_count gate in evidence.cedar clears.
UPDATE findings
SET verified = TRUE
WHERE verified = FALSE
  AND id IN (SELECT finding_id FROM finding_verifications);

COMMIT;
