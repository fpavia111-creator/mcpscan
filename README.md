> **Moved:** this project has been renamed to **Argus of MCP** and now lives at https://github.com/fpavia111-creator/argus.
>
> Install the new package: `npm i @kurtfrancisco/argus`. `@kurtfrancisco/mcpscan` is deprecated and gets no further updates; the old commands, env vars and license keys still work in Argus of MCP.

# mcpscan — MCP server & agent-skill supply-chain scanner (MVP)

[![CI](https://github.com/fpavia111-creator/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/fpavia111-creator/mcpscan/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@kurtfrancisco/mcpscan.svg)](https://www.npmjs.com/package/@kurtfrancisco/mcpscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.fpavia111--creator%2Fmcpscan-blue)](https://registry.modelcontextprotocol.io)

> Supply-chain security scanner for MCP servers and agent skills (Claude, Cursor, VS Code, Windsurf).

## Quickstart

**Install** (Node.js ≥ 18):

```bash
npm install -g @kurtfrancisco/mcpscan   # or: npx @kurtfrancisco/mcpscan scan
```

**Claude Code**

```bash
claude mcp add mcpscan -- npx -y @kurtfrancisco/mcpscan@0.1.0 mcp
```

**Cursor** — add to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (project). The same snippet works for Claude Desktop, VS Code and Windsurf:

```json
{ "mcpServers": { "mcpscan": { "command": "npx", "args": ["-y", "mcpscan@0.1.0", "mcp"] } } }
```

Restart the client and the tools appear. Full details below.


Teams install third-party **MCP servers** and **agent skills** (Claude Code skills, plugin skills, Cursor skills) the same way they once installed random npm packages: copy a JSON snippet, run `npx -y something`, and trust it. Those components can be **dead**, **over-privileged**, or can **hide prompt injection** in a `SKILL.md` or a tool description.

`mcpscan` is a zero-dependency Node.js CLI that finds every MCP config and skill folder on a machine (Windows, macOS, Linux), runs offline static checks, and writes **text / JSON / SARIF / HTML** reports with CI-friendly exit codes. It can also run as a **read-only MCP server** so an agent can audit its own environment.

> Status: MVP. Static, pattern-based analysis. Read [Limitations](#limitations) before relying on it.

## What it finds

| Rule | Default sev. | Check |
|---|---|---|
| MCP001 | high | Prompt injection / hidden instructions ("ignore previous instructions", "do not tell the user", `<IMPORTANT>` tags, instructions inside HTML comments, "bypass safety") in SKILL.md, docs, and tool descriptions |
| MCP002 | high / critical | Zero-width, bidi-override, and Unicode **tag** characters (tag text is decoded and shown) |
| MCP003 | critical | Instructions to send data to an external endpoint or harvest credentials |
| MCP004 | high / critical | Dangerous commands in scripts, SKILL.md code blocks, and server command lines: `curl … \| sh`, `iwr … \| iex`, `rm -rf ~`, `Remove-Item -Recurse -Force`, `base64 -d \| sh`, reverse shells, persistence |
| MCP005 | high | Credential paths: `~/.ssh/id_*`, `~/.aws/credentials`, `.kube/config`, browser `Login Data`, `.netrc`, `%USERPROFILE%\.ssh\…` |
| MCP006 | medium | Large base64 blobs (possible obfuscated payloads) |
| MCP007 | high / critical | Hardcoded secrets in `env`, `headers`, args, URLs, and skill files (GitHub, Anthropic, OpenAI-style, AWS, Slack, Stripe, GitLab, npm, xAI, JWT, DB URLs, private keys). **Values are always masked** (first 4 chars + length) |
| MCP008 | low–high | Unpinned packages: `npx -y pkg`, `pkg@latest`, ranges like `^1.2.0`, `uvx pkg`, `docker image:latest` (handles `cmd /c npx.cmd …` on Windows) |
| MCP009 | high (info for localhost) | Plain `http://` / `ws://` remote transport, secrets in URL query strings |
| MCP010 | medium / high | Excessive filesystem roots (`/`, `C:\`, `~`, `%USERPROFILE%`, the whole home dir) and dangerous docker mounts (`/`, `docker.sock`) |
| MCP011 / MCP012 | high / medium | Policy deny-list hit / not on allow list |
| MCP013–016 | varies | `--online` only: npm deprecated, stale (no publish in 365 days), GitHub repo archived/missing, package missing from registry |
| MCP017 | low | Config file could not be parsed |
| MCP018 | info | SKILL.md missing `name`/`description` frontmatter |

`mcpscan rules` prints the catalog.

## Where it looks

| Client | Windows | macOS | Linux |
|---|---|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` | `~/Library/Application Support/Claude/…` | `~/.config/Claude/…` |
| Claude Code | `%USERPROFILE%\.claude.json` (user + per-project servers), `%USERPROFILE%\.claude\settings.json` | `~/.claude.json`, `~/.claude/settings.json` | same |
| Cursor | `%USERPROFILE%\.cursor\mcp.json` | `~/.cursor/mcp.json` | same |
| VS Code (+ Insiders, VSCodium) | `%APPDATA%\Code\User\mcp.json` and `settings.json` (`mcp.servers`) | `~/Library/Application Support/Code/User/…` | `~/.config/Code/User/…` |
| Windsurf | `%USERPROFILE%\.codeium\windsurf\mcp_config.json` | `~/.codeium/windsurf/mcp_config.json` | same |
| Project | `.mcp.json`, `.cursor\mcp.json`, `.vscode\mcp.json`, `.windsurf\mcp.json` | same | same |
| Skills | `%USERPROFILE%\.claude\skills`, `%USERPROFILE%\.claude\plugins\**\skills`, `%USERPROFILE%\.cursor\skills`, project `.claude\skills` | `~/.claude/...` | same |

Run `mcpscan paths` to see the exact paths checked on your OS. JSONC (comments, trailing commas) is supported. Symlinks are never followed.

## Install & use

Needs Node.js 18 or newer. No runtime dependencies, so you don't have to run `npm install` to use it.

### Windows (PowerShell)

```powershell
# from the folder you copied (e.g. C:\path\to\mcpscan)
cd $env:USERPROFILE\mcp-skill-scanner
node .\bin\mcpscan.js paths                       # where it will look
node .\bin\mcpscan.js scan                        # user configs + current folder
node .\bin\mcpscan.js scan -p C:\code\my-repo -f html -o "$env:TEMP\mcpscan.html"
Start-Process "$env:TEMP\mcpscan.html"
npm test                                          # run the test suite (offline)

# optional: put `mcpscan` on PATH
npm link
mcpscan scan --fail-on critical
$LASTEXITCODE                                     # 0 = clean, 1 = findings, 2 = error
```

If PowerShell blocks the `mcpscan.ps1` shim that `npm link` creates, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or keep calling `node .\bin\mcpscan.js`.

### macOS / Linux

```bash
node bin/mcpscan.js scan
node bin/mcpscan.js scan -p ~/code/app -f sarif -o mcpscan.sarif
```

### Options

```
mcpscan [scan] [-p dir]... [-c config.json]... [-s skillsDir]... [-t tools.json]...
        [-f text|json|sarif|html] [-o file] [--fail-on critical|high|medium|low|info|none]
        [--min-severity sev] [--policy file] [--online] [--root home] [--platform win32|darwin|linux]
        [--no-default-roots] [--no-color]
mcpscan list | paths | rules | init-policy | mcp
```

- **Vet a skill before installing:** `mcpscan scan --no-default-roots -s .\downloaded-skill`
- **Vet tool descriptions:** save a server's `tools/list` result to JSON, then `mcpscan scan --no-default-roots -t tools.json`
- **Exit codes:** `0` = nothing at or above `--fail-on` (default `high`, or `failOn` from the policy), `1` = findings, `2` = usage/runtime error.

### CI (GitHub Actions + code scanning)

```yaml
- run: node bin/mcpscan.js scan --no-default-roots -p . -f sarif -o mcpscan.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: mcpscan.sarif }
```

## Policy file (`mcpscan.policy.json`)

Loaded from the current directory, or pass `--policy path`. `mcpscan init-policy` writes a starter file.

```json
{
  "version": 1,
  "failOn": "high",
  "requireAllowList": false,
  "allow": { "servers": [], "packages": ["@modelcontextprotocol/*"], "hosts": ["mcp.linear.app"], "skills": [] },
  "deny":  { "servers": [], "packages": ["*-mcp-free-*"], "hosts": ["*.ngrok-free.app"], "skills": [] },
  "ignore": [ { "rule": "MCP018" }, { "rule": "MCP008", "target": "internal-*" } ],
  "severityOverrides": { "MCP014": "low" }
}
```

`*` is a wildcard. When `requireAllowList` is `true`, any server or skill that isn't allow-listed raises MCP012.

## MCP server mode (read-only)

`mcpscan mcp` runs a stdio MCP server (JSON-RPC 2.0, protocol `2025-06-18`) with four tools, each annotated `readOnlyHint: true`: `scan_all`, `list_discovered`, `scan_skill`, `scan_text`. None of them writes files or touches the network.

```json
{ "mcpServers": { "mcpscan": { "command": "node", "args": ["C:\\path\\to\\mcpscan\\bin\\mcpscan.js", "mcp"] } } }
```

Claude Code: `claude mcp add mcpscan -- node /path/to/mcpscan/bin/mcpscan.js mcp`

## Claude Code skill

`skills/mcpscan/` holds a ready-made skill (`SKILL.md` + `reference.md`). Copy the folder into `%USERPROFILE%\.claude\skills\` (Windows) or `~/.claude/skills/` (macOS/Linux), or into a repo's `.claude/skills/`:

```powershell
Copy-Item -Recurse .\skills\mcpscan "$env:USERPROFILE\.claude\skills\mcpscan"
```

## Competitors and prior art

- **mcp-scan / Snyk Agent Scan** by Invariant Labs, acquired by Snyk on June 24, 2025. It discovers MCP servers and skills and scans tool descriptions for tool poisoning, rug pulls, and cross-origin escalation. It connects to servers and sends tool names and descriptions to a remote analysis API. Snyk also offers a background mode that reports to Snyk Evo for company-wide monitoring.
  - Repo: https://github.com/invariantlabs-ai/mcp-scan
  - Launch post: https://invariantlabs.ai/blog/introducing-mcp-scan
  - Acquisition: https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/
- **Cisco AI Defense mcp-scanner**, which scans MCP servers for threats: https://github.com/cisco-ai-defense/mcp-scanner

**How mcpscan differs:** it runs fully offline by default and sends no tool descriptions to a third party. It has zero dependencies, so it's easy to audit. It covers supply-chain hygiene (pinning, secrets, filesystem scope, transport, liveness) as well as injection. It produces native SARIF for CI, applies a simple policy file, and covers Windows paths explicitly. Its trade-off: no LLM-based semantic analysis, and it doesn't connect to live servers.

## Limitations

- Detection is regex/heuristic. Expect false positives. Skills that legitimately say "do not tell the user X" get flagged MCP001. Expect false negatives too: paraphrased or translated injections, payloads split across files, and obfuscation beyond base64 and hidden Unicode get through.
- Tool descriptions are only checked when they appear in a config, or when you pass a `tools/list` dump with `-t`. mcpscan doesn't launch or connect to servers, so it can't detect rug pulls (description changes over time).
- `--online` checks npm and GitHub only. PyPI and Docker Hub liveness aren't implemented, and unauthenticated GitHub API calls are rate-limited (60 requests/hour).
- Config paths cover the clients' current documented defaults. Portable installs, custom `CLAUDE_CONFIG_DIR`, and enterprise-managed settings aren't discovered automatically; pass them with `-c`/`-s`.
- Homoglyph and confusable-character detection isn't implemented.
- The MCP server mode implements tools only (no resources or prompts) over stdio.

## Development

```bash
npm run build   # syntax-check all files, load modules, validate policy JSON
npm test        # node:test, fully offline (fetch is stubbed to throw)
npm run demo    # scan the bundled malicious fixtures
node scripts/make-fixtures.js   # regenerate fixtures (all secrets are fake)
```

## License

MIT © 2026 Kurt Francisco. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome at https://github.com/fpavia111-creator/mcpscan. See [CONTRIBUTING.md](CONTRIBUTING.md).
