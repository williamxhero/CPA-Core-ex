# Provider runtime key-match challenge

This additive Core #82 seam is not completion of monetary policy, funding
coverage, account identity, shared-wallet identity, or balance retrieval. It
never contacts an upstream service and does not modify inference gates.
Existing provider eligibility and S1 behavior remain unchanged.

## Frozen wire

`POST /v8/management/inference-gates/providers/key-match` requires the existing
management administrator credential and returns `Cache-Control: no-store`,
including rejected requests. The JSON request contains exactly:

- `version`: `1`
- `scope`, `targets`: the complete parent-first provider Binding returned by
  provider eligibility (not a member subset or a credential Binding)
- `sourceVersion`: that current provider group's source revision
- `auth_index`: one actual current member's locator
- `adapter`: `deepseek`
- `nonce`: a canonical UUID
- `digest`: lowercase HMAC-SHA256 hex, keyed by the query credential

The HMAC message is UTF-8, with no final newline:

```text
cpa-provider-key-match-v1\n<nonce>\n<sourceVersion>\n<auth_index>
```

The success JSON echoes `version`, `scope`, `targets`, `sourceVersion`,
`auth_index`, `nonce`, and `adapter`, and adds only
`authority: "runtime_key_match_only"` and boolean `matched`. A different query
credential returns HTTP 200 with `matched: false`; it does not establish a
different account or any monetary conclusion. No response contains a key,
challenge digest, endpoint, or stable key fingerprint.

This is an online equality check, not a persistent certificate or a replay
prevention mechanism. Core does not persist/consume nonces: repeating the same
request may return the same answer while the complete context remains current.
The caller must generate a fresh nonce and bind its consumption to its own
current operation; an earlier receipt does not bypass current source checks.
No anti-replay, credential-acquisition time, or financial freshness claim is
made by this endpoint.

## Runtime validation

The whole group must have current complete route coverage. Every runtime
member is rebound from the current actual source, discarding any borrowed
Binding before binding. The selected member must use the actual native
OpenAI-compatible executor, which resolves the same `base_url` and `api_key`
attributes as inference. Labels, config indices, group names, and structural
executor impersonation cannot substitute for this authority. Custom headers
and plugin sources are not supported by this slice.
Missing runtime Bindings and multiple live claimants for an issued child are
rejected rather than resolving authority by locator or iteration order.

For every member, both the opening and closing validation resolve the executor
through the auth manager's actual inference dispatch selector, including
`compat_name` / `provider_key` precedence and canonicalization. The selected
native executor must agree with the executor covered by the issued routing
receipt. Missing dispatch, redirected wrappers and a different native executor
fail closed even if the frozen S1 routing receipt/source revision is unchanged.
The S1 coverage policy and the wire/HMAC contract are not changed by this check.

Only literal `https://api.deepseek.com` inference bases qualify: optional `/v1`,
optional final slash, optional explicit default `:443`. Userinfo, query,
fragment, escaped/other paths, different hosts, and nondefault ports fail
closed. Missing keys and unissued runtime substitutions cannot match.

Before responding, Core repeats the complete group and source checks and the
native executor match. The endpoint does not fetch a balance or infer monetary
coverage for the rest of the group, even if a selected key matches.

## Failure statuses

- `400 invalid_query`: malformed, missing, unknown, duplicate, case-shadowed,
  null, over-32-KiB, or non-UTF-8 wire data; invalid version/adapter/nonce/digest
- `409 gate_conflict`: stale/different scope, targets or group source revision;
  non-member locator, forged source, or inconsistent closing validation
- `422 key_match_unsupported`: unsupported actual executor credential/origin
- `503 gate_unavailable`: unavailable catalog or incomplete actual runtime/routes
- Existing management middleware supplies unauthorized/disabled/Home failures.

## Bounded verification

`internal/api/provider_key_match_test.go` exercises the registered public API
with the actual catalog, watcher, auth manager and native executor using only
synthetic credentials. It covers positive and negative HMACs, both group
members, official base variants, unsupported origins, stale and incomplete
proofs, non-members, forged selected/sibling sources, missing keys, header
overrides, partial runtime routes, authentication, strict JSON, no mutation,
and real access/request logging with blocked business/quota egress.
Public dispatch regressions cover selected and sibling members, missing,
wrapped and different native executors, both selector attributes, deterministic
closing drift at the request cancellation boundary, and canonical selector
controls. All dispatch cases trap business and quota network access.

The candidate's ordinary `cmd/server` binary, commit/SHA-256 pin, offline
commands, raw RED/GREEN and failed-attempt logs are retained outside this
worktree under `provider82-funding-core-evidence`. The canonical S1 artifact
is not replaced. Manager policy and its native acceptance remain separately
owned; this receipt does not attest their SQLite state or applied gate ACK.
