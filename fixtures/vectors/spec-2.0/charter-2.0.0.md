# Domokos Neutrality Charter

**Version:** 2.0.0
**Effective date:** 2026-10-11
**Status:** In force. Supersedes v1.0.0 in full.

## Why this version exists

Version 1.0.0 contained a clause permitting the operator to perform
fee-for-labour assessment work for assessment firms. No such work was
performed, and that clause is deleted. Version 2.0.0 commits Domokos to
serving one side only: the organisations that are assessed.

This document is hashed and recorded in the Domokos evidence ledger, subject
to the same chain rules as every other entry. Retrieve it with `GET /charter`.

## Clauses

1. **One side only.** Domokos takes no revenue of any kind from assessment
   bodies, notified bodies or technical services while it serves
   organisations they assess.

2. **Switching sides.** If Domokos ever sells to assessment bodies, notified
   bodies or technical services, it first stops serving assessed
   organisations. The switch is announced with notice and recorded in the
   ledger.

3. **Domokos never assesses.** Domokos does not conduct assessments, audits
   or homologation activities and never issues conformity statements. The
   product records and maps evidence; assessment and conformity decisions are
   made by people.

4. **What Domokos builds, Domokos never attests.** Artefacts Domokos builds
   for a client in an engineering engagement are never reviewed or attested
   by Domokos. This is to be enforced in the product by the engagement
   registry (REQ-COR-05), scheduled for the P2 build stage; until it ships,
   this clause is a commitment, not a technical control.

5. **Assessor interviews.** Interviews with assessors are paid for by
   Domokos, the interviewees are anonymised, and what they say is used only
   as aggregated patterns (REQ-COR-06, scheduled for the corpus build stage).

6. **No engagement data in the corpus.** No data, finding, document or
   observation from any consulting or engineering engagement enters the
   acceptance corpus. Corpus rows carrying the provenance
   `consulting_engagement` are rejected at the write boundary and by a
   database constraint; an automated test proves the rejection.

7. **No investment or influence.** Domokos does not accept investment,
   equity or revenue-for-influence from an assessment body, notified body,
   technical service, Tier 1 supplier or vehicle software producer, and will
   not be majority-owned by any of them.

8. **Amendment.** Amending this charter requires a new semantic version and a
   new ledger record; every prior version stays verifiable. A CI gate refuses
   a changed charter without a version bump and a matching record. (Moving
   that gate onto the ledger record inside an exported bundle is REQ-QA-05,
   scheduled for the P1 build stage.)

## Historical note

Version 1.0.0 (effective 2026-08-24) is superseded by this version, not
replaced in place: its hash and ledger references remain in
`docs/charter_records.json`.
