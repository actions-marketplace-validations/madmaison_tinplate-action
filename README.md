# Tinplate AI Safety, Secret & MCP Security Gate

Run **Tinplate**'s offline deterministic, zero-logging edge AI security checks directly in your GitHub Actions CI/CD pipelines.

> **Official Public Repository & Issue Tracker:** This repository hosts `tinplate-action` and serves as the public GitHub repository and issue tracker for **[`@tinplate/sdk`](https://www.npmjs.com/package/@tinplate/sdk)** (TypeScript/JS), **[`tinplate`](https://pypi.org/project/tinplate/)** (Python), and the **[Hosted MCP Server](https://tinplate.dev/sdk#config-generator)** (`https://api.tinplate.dev/mcp`). Tinplate's Cloudflare Workers runtime monorepo (`tinspace/tinplate`) is maintained privately.
>
> - **Service Policy:** Tinplate APIs, MCP endpoints, and SDKs are **provided as-is, best-effort, no SLA unless agreed in a written Business/Enterprise contract** ([`tinplate.dev/pricing#enterprise`](https://tinplate.dev/pricing#enterprise)).
> - **Support & Enterprise:** [`support@tinplate.dev`](mailto:support@tinplate.dev) ([tinplate.dev/support](https://tinplate.dev/support))
> - **Private Security & PGP Disclosure:** Never file vulnerabilities as public GitHub issues — email [`security@tinplate.dev`](mailto:security@tinplate.dev) using our [PGP Public Key](https://tinplate.dev/.well-known/pgp-key.asc) ([Trust Center](https://tinplate.dev/security) · [`security.txt`](https://tinplate.dev/.well-known/security.txt)).

## Use Cases
- **Secret Scanning (`/v1/secret-scanner`)**: Catch leaked API keys, tokens, PEM keys, and high-entropy credentials in PR diffs.
- **MCP Server Manifest Linting (`/v1/mcp-manifest-linter`)**: Audit `mcp.json` / tool definitions for tool poisoning, "Lethal Trifecta" capability combinations, and SSRF risks.
- **AI-Generated Code & CI Guard (`/v1/agent-code-guard`)**: Statically audit LLM-generated Python, JS/TS, Bash, or GitHub Actions YAML before execution.
- **Regex ReDoS Auditor (`/v1/regex-safety`)**: Catch catastrophic backtracking before shipping regular expressions.
- **Turnkey Presets (`llm-ingest-safe`, `llm-output-safe`, `agent-pre-exec`)**: Run multi-step security bundles in 1 call with cryptographic audit receipts (`?receipt=true`).

## Usage

### Example 1 — Secret Scanner via RapidAPI

```yaml
- name: Tinplate Secret Scan
  uses: tinspace/tinplate-action@v1
  with:
    api_key: ${{ secrets.RAPIDAPI_KEY }}
    provider: rapidapi
    rapidapi_host: log-redact-and-secret-scanner-api.p.rapidapi.com
    endpoint: /v1/secret-scanner
    payload: '{"text":"${{ github.event.head_commit.message }}","mode":"mask"}'
    fail_on_block: "true"
```

### Example 2 — Agent Pre-Execution Preset via Direct Polar (`tp_...`) or Zyla Bearer Key

```yaml
- name: Tinplate Agent Security Gate
  uses: tinspace/tinplate-action@v1
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
| `preset` | No | `""` | Optional preset (`llm-ingest-safe`, `llm-output-safe`, `agent-pre-exec`) |
| `endpoint` | No | `/v1/secret-scanner` | Target `/v1/*` endpoint (ignored if `preset` is set) |
| `payload` | Yes | — | JSON string payload |
| `fail_on_block` | No | `true` | Fail the workflow step when verdict triggers policy failure |
| `fail_on` | No | `block` | Failure threshold: `block` (default) or `review` (fails on `review` OR `block`) |
| `print_response` | No | `false` | Print full JSON response body to workflow logs (default `false` to avoid exposing unredacted tokens/text) |

## SDKs & Hosted MCP Server

- **TypeScript / JavaScript (`npm install @tinplate/sdk`)**: Zero-dependency client (`v2.0.0`) for Node 18+, Cloudflare Workers, Deno, Bun, Vercel AI SDK, OpenAI, and Anthropic, including offline Ed25519/ES256 JWKS receipt verification (`verifyReceiptOffline()`).
- **Python (`pip install tinplate`)**: Zero-dependency stdlib client (`v2.0.0`) with built-in adapters for LangChain, LlamaIndex, CrewAI, and PydanticAI.
- **Streamable HTTP MCP (`https://api.tinplate.dev/mcp`)**: Exposes 7 free tools keyless, 17 x402 Base Mainnet USDC pay-per-call tools, and all 30 tools (26 APIs) with `Authorization: Bearer tp_...`.

## Links
- Tin Suite Hub: https://tinspace.dev
- Pure-Security 26-API Catalog: https://tinplate.dev/#apis
- MCP Security & LLM Guardrail Bundles: https://tinplate.dev/solutions/mcp-security
- SDKs, MCP Config Generator & Docs: https://tinplate.dev/sdk#config-generator
- Postman v2.1 Collection: https://tinplate.dev/postman.json
- Direct All-Access & Business/Enterprise Plans: https://tinplate.dev/pricing
- Security & Trust Center (OWASP Top 10, Ed25519 JWKS, PGP): https://tinplate.dev/security
- Standard DPA & Sub-Processors: https://tinplate.dev/dpa
- Support & Bug Tracker: [`support@tinplate.dev`](mailto:support@tinplate.dev) · [Issues](https://github.com/tinspace/tinplate-action/issues)
- Sibling Suite: TinLab (https://tinlab.dev) · TinTrace (https://tintrace.dev)
