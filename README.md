# Tinplate AI Safety, Secret & MCP Security Gate

Run **Tinplate**'s deterministic, zero-logging edge security & compliance checks directly in your GitHub Actions CI/CD pipelines.

## Use Cases
- **Secret Scanning (`/v1/secret-scanner`)**: Catch leaked API keys, tokens, PEM keys, and high-entropy credentials in PR diffs.
- **MCP Server Manifest Linting (`/v1/mcp-manifest-linter`)**: Audit `mcp.json` / tool definitions for tool poisoning, "Lethal Trifecta" capability combinations, and SSRF risks.
- **AI-Generated Code & CI Guard (`/v1/agent-code-guard`)**: Statically audit LLM-generated Python, JS/TS, or GitHub Actions YAML before execution.
- **Regex ReDoS Auditor (`/v1/regex-safety`)**: Catch catastrophic backtracking before shipping regular expressions.
- **Turnkey Presets (`llm-ingest-safe`, `llm-output-safe`, `agent-pre-exec`, `eu-vendor-kyb`)**: Run multi-step policy bundles in 1 call with cryptographic compliance receipts (`?receipt=true`).

## Usage

### Example 1 — Secret Scanner via RapidAPI

```yaml
- name: Tinplate Secret Scan
  uses: madmaison/tinplate-action@v1
  with:
    api_key: ${{ secrets.RAPIDAPI_KEY }}
    provider: rapidapi
    rapidapi_host: log-redact-and-secret-scanner-api.p.rapidapi.com
    endpoint: /v1/secret-scanner
    payload: '{"text":"${{ github.event.head_commit.message }}","mode":"mask"}'
    fail_on_block: "true"
```

### Example 2 — Agent Pre-Execution Preset via Direct / Zyla Bearer Key

```yaml
- name: Tinplate Agent Security Gate
  uses: madmaison/tinplate-action@v1
  with:
    api_key: ${{ secrets.TINPLATE_API_KEY }}
    provider: bearer
    preset: agent-pre-exec
    payload: '{"input":"rm -rf /"}'
    fail_on_block: "true"
```

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `api_key` | Yes | — | RapidAPI Key, Zyla API Key, or Direct Bearer Key |
| `provider` | No | `rapidapi` | `rapidapi`, `zyla`, or `bearer` |
| `rapidapi_host` | No | `""` | RapidAPI host (`*.p.rapidapi.com`) when `provider` is `rapidapi` |
| `base_url` | No | `https://api.tinplate.dev` | Override target base URL |
| `preset` | No | `""` | Optional preset (`llm-ingest-safe`, `llm-output-safe`, `agent-pre-exec`, `eu-vendor-kyb`) |
| `endpoint` | No | `/v1/secret-scanner` | Target `/v1/*` endpoint (ignored if `preset` is set) |
| `payload` | Yes | — | JSON string payload |
| `fail_on_block` | No | `true` | Fail the workflow step when `verdict == "block"`, `safe == false`, or `all_passed == false` |

## Links
- Full 42-API Catalog: https://tinplate.dev/apis
- SDKs & Docs: https://tinplate.dev/sdk
