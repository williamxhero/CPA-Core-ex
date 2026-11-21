# AGENTS.md

Go 1.26+ proxy server providing OpenAI/Gemini/Claude/Codex compatible APIs with OAuth and round-robin load balancing.

## Repository
- GitHub: https://github.com/router-for-me/CLIProxyAPI

## Commands
```bash
gofmt -w . # Format (required after Go changes)
go build -o cli-proxy-api ./cmd/server # Build
go run ./cmd/server # Run dev server
go test ./... # Run all tests
go test -v -run TestName ./path/to/pkg # Run single test
go build -o test-output ./cmd/server && rm test-output # Verify compile (REQUIRED after changes)
```
- Common flags: `--config <path>`, `--tui`, `--standalone`, `--local-model`, `--no-browser`, `--oauth-callback-port <port>`

## Deployment
- CPA runtime work is local-only. Keep the small computer/yosef-server outside the scope of investigation, repair, and deployment.
- After every bug fix that changes CPA-Core, deploy to the local machine with `D:\WILL\AGENT\CPA\ops\deploy-local-cpa-core.ps1`.
- The deployment must create a backup, replace the live binary, restart the local CPA stack, and pass all readiness checks. Any failure must automatically restore the previous binary and restart the previous stack before reporting failure.

## Inference gates
- `AdmitInference` may deny only a **current-lifecycle** credential gate. A `reconciliation_required` / drifted incarnation must never fail-closed as unavailable after quota recovers.
- Credential pause/clear ownership is the **primary resource id** (`targets[0]`), not full projection membership or incarnation equality. Manager recover/resume must clear `reconciliation_required` rows on that same slot.

## Config
- Default config: `config.yaml` (template: `config.example.yaml`)
- `.env` is auto-loaded from the working directory
- Auth material defaults under `auths/`
- Storage backends: file-based default; optional Postgres/git/object store (`PGSTORE_*`, `GITSTORE_*`, `OBJECTSTORE_*`)

## Architecture
- `cmd/server/` — Server entrypoint
- `internal/api/` — Gin HTTP API (routes, middleware, modules)
- `internal/api/modules/amp/` — Amp integration (Amp-style routes + reverse proxy)
- `internal/thinking/` — Main thinking/reasoning pipeline. `ApplyThinking()` (apply.go) parses suffixes (`suffix.go`, suffix overrides body), normalizes config to canonical `ThinkingConfig` (`types.go`), normalizes and validates centrally (`validate.go`/`convert.go`), then applies provider-specific output via `ProviderApplier`. Do not break this "canonical representation → per-provider translation" architecture.
- `internal/runtime/executor/` — Per-provider runtime executors (incl. Codex WebSocket)
- `internal/translator/` — Provider protocol translators (and shared `common`)
- `internal/registry/` — Model registry + remote updater (`StartModelsUpdater`); `--local-model` disables remote updates
- `internal/store/` — Storage implementations and secret resolution
- `internal/managementasset/` — Config snapshots and management assets
- `internal/cache/` — Request signature caching
- `internal/watcher/` — Config hot-reload and watchers
- `internal/wsrelay/` — WebSocket relay sessions
- `internal/usage/` — Usage and token accounting
- `internal/home/` — CLIProxyAPIHome control plane integration (bootstrap, RESP communication, dispatch coordination)
- `internal/tui/` — Bubbletea terminal UI (`--tui`, `--standalone`)
- `sdk/cliproxy/` — Embeddable SDK entry (service/builder/watchers/pipeline)
- `test/` — Cross-module integration tests

## Code Conventions
- Keep changes small and simple (KISS)
- Comments in English only
- If editing code that already contains non-English comments, translate them to English (don’t add new non-English comments)
- For user-visible strings, keep the existing language used in that file/area
- New Markdown docs should be in English unless the file is explicitly language-specific (e.g. `README_CN.md`)
- As a rule, do not make standalone changes to `internal/translator/`. You may modify it only as part of broader changes elsewhere.
- If a task requires changing only `internal/translator/`, run `gh repo view --json viewerPermission -q .viewerPermission` to confirm you have `WRITE`, `MAINTAIN`, or `ADMIN`. If you do, you may proceed; otherwise, file a GitHub issue including the goal, rationale, and the intended implementation code, then stop further work.
- `internal/runtime/executor/` should contain executors and their unit tests only. Place any helper/supporting files under `internal/runtime/executor/helps/`.
- Do not use `github.com/tidwall/gjson`, `github.com/tidwall/sjson`, Go's standard `encoding/json`, Go's standard `encoding/base64`, or Go's standard `regexp`. Always use `github.com/MoeForge/moego/json`, `github.com/MoeForge/moego/ojson`, `github.com/MoeForge/moego/base64`, and `github.com/MoeForge/moego/regexp` for all JSON, Base64, and regular expression operations. All JSON write operations (`Set`, `SetRaw`, `Delete`, etc.) MUST be performed on `*ojson.Doc` (`ojson.NewDoc` / `ojson.NewDocString`), passing `*ojson.Doc` across mutation stages and serializing only once at the final exit (`doc.Bytes()` / `doc.String()`), rather than mutating raw `[]byte` or `string` payloads directly.
- Payload configuration MUST be the final semantic barrier before sending requests in every executor, including streaming, WebSocket, continuation, retry/fallback, image, and token-count paths where applicable. Complete all built-in payload translation, normalization, injection, and cleanup first, then evaluate and apply user payload rules exactly once to the final business payload. No subsequent logic may overwrite configured values or restore filtered fields. Only necessary transport framing, serialization, signature calculation, and read-only validation may follow without changing business payload semantics. Add regression tests when introducing or changing request-building paths to enforce this ordering.
- Follow `gofmt`; keep imports goimports-style; wrap errors with context where helpful
- Do not use `log.Fatal`/`log.Fatalf` (terminates the process); prefer returning errors and logging via logrus
- Shadowed variables: use method suffix (`errStart := server.Start()`)
- Wrap defer errors: `defer func() { if err := f.Close(); err != nil { log.Errorf(...) } }()`
- Use logrus structured logging; avoid leaking secrets/tokens in logs
- Avoid panics in HTTP handlers; prefer logged errors and meaningful HTTP status codes
- Timeouts are allowed only during credential acquisition; after an upstream connection is established, do not set timeouts for any subsequent network behavior. Intentional exceptions that must remain allowed are the Codex websocket liveness deadlines in `internal/runtime/executor/codex_websockets_executor.go`, the wsrelay session deadlines in `internal/wsrelay/session.go`, the management APICall timeout in `internal/api/handlers/management/api_tools.go`, and the `cmd/fetch_antigravity_models` utility timeouts
- Avoid wall-clock `time.Sleep` in TTL, expiration, ordering, or cache-eviction unit tests due to platform timer granularity (e.g. Windows default timer resolution of ~15.6ms) and CI jitter under load; prefer controllable clocks (`nowFunc` / mock clock), explicit timestamp manipulation, or deterministic synchronization primitives.
- Note: if modifying features that involve CLIProxyAPIHome, check if corresponding updates are needed in the CLIProxyAPIHome repository.
- Endpoints under the `/v0/management` base URL are deprecated and no longer maintained. For any feature changes, do not modify endpoints under `/v0/management` unless necessary to fix compilation errors.
## Version

- `VERSION` holds the composed identity `{source}+{ex}`, for example `8.0.76+1.0.0`: the newest tag from router-for-me/CLIProxyAPI without its `v`, plus this fork's own semantic version.
- Every requirement that changes this repository ships a version change: run `D:\WILL\AGENT\CPA\ops\update-versions.ps1 -BumpChanged` before committing, or `-BumpEx minor|major` / `-ExVersion x.y.z` when a patch is too small. Merging the source repository refreshes the source part with a plain run. The script rewrites `VERSION` and the generated Go constant that ordinary `go build` compiles.
- `D:\WILL\AGENT\CPA\ops\update-versions.ps1 -Check` must pass before the task is reported finished.
- Never edit the `version_generated.go` file by hand. A test rejects an identity that is not `{source}+{ex}`.
- `-ldflags -X` still overrides the compiled version, but local deployments must rely on the checked-in identity so the running stack reports what was merged.

## 自有 fork 首页与 GitHub About

仅适用于自有远端仓库名以 `-ex` 结尾的 fork。根 README.md 用中文说明相对上游已交付的改进、解决的问题、使用位置和方法，不复述通用安装配置。外部项目首次出现时链接项目主页；集合中的具体组件直接链接其 README 或目录。上游英文原文单独保存在 README-source.md，移动后修正并检查相对链接。首页只留一个上游基础用法入口：优先中文版，否则链接可用版本并标明语言。

合并上游时，将上游 README 的变化同步到归档；即使无冲突，提交前也要将 fork 首页与合并前版本比较，除非用户另有要求，保持首页不变。交付大功能后先更新首页，再从全部已交付功能中按用户价值重选三项，用具体、简短的中文收益更新 GitHub About 并回读确认。三项限制不适用于 README。
