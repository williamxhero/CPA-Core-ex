---
title: Protect confirmed provider pauses during Core rollback
date: 2026-11-21
category: integration-issues
module: CPA Core resource catalog
problem_type: integration_issue
component: api_layer
symptoms:
  - An older management page can set auto-held to false while the predecessor Core is running.
  - A protected prepaid route can receive an attempt even though applicable funding evidence is missing.
root_cause: missing_validation
resolution_type: migration
severity: high
tags: [provider-funding, rollback, legacy-auto-held, routing]
---

# Protect confirmed provider pauses during Core rollback

## Problem

A configuration guard on the current Core cannot stop a previous Core from accepting the same legacy write. A rollback must preserve the effective system pause for the affected prepaid access.

## Symptoms

With only the legacy marker protecting a synthetic route, the actual installed predecessor accepted a legacy management PATCH setting `auto-held` to false. After restarting that predecessor on the mutated configuration, the next request attempted the protected route before using the healthy fallback. The fixture counted connection attempts on a local proxy and did not forward to a paid upstream.

## What Didn't Work

Rejecting legacy writes in the new binary is insufficient: the rollback replaces the binary and its write guard. A successful UI readback of the latest flags also does not prove admission behavior during rollback.

## Solution

- In `internal/resourcecatalog/legacy_funding_gate.go`, record existing legacy pauses as independently owned entries in the existing signed v1 ledger. Keep the ledger, its seal key, both gate-floor-v1 anchor records and the source backups through rollback.
- In current Core, interpret the migration owner as a rollback guard only when every current member has a positive receipt for the exact current target and adapter in the same catalog instance and incarnation, with an observation newer than that generation guard. A missing receipt or one older than that guard does not release it. The prior ledger entry is retained for the predecessor. An independent operator pause is unchanged.
- In `internal/api/handlers/management/legacy_funding_config.go`, reject legacy edits to native-owned markers on current Core. This is defense in depth; runtime admission remains the safety check.

## Why This Works

The predecessor already understands the signed gate format. It denies the affected credential without relying on the writable YAML flag. Current Core understands the new release evidence and exposes a released migration entry as `rollback_guard` in `internal/resourcecatalog/gate.go`; that projection is not a deletion of the predecessor's gate.

## Prevention

When testing this cutover, restart the exact previously installed binary with the same temporary disk, stop current evidence producers, and make the old authenticated request that attempts to clear the flag. Verify both that the old binary really accepted the flag write and that no inference attempt reaches the held route; check the healthy fallback separately. Restart the candidate and verify reconciliation after a source change and release with fresh evidence. This result only supports predecessors that enforce the same signed v1 credential gates.

## Related Issues

- [CPA #65: quota recheck and legacy funding authority cutover](https://github.com/williamxhero/CPA/issues/65)
