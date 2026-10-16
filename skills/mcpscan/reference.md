# mcpscan rule reference

| Rule | Default severity | Meaning |
|------|------------------|---------|
| MCP001 | high | Prompt-injection / hidden instruction phrase |
| MCP002 | high/critical | Zero-width, bidi, or Unicode tag characters (critical when tag text is hidden) |
| MCP003 | critical | Instruction to send data to an external endpoint or harvest credentials |
| MCP004 | high/critical | Dangerous command: piping a download into a shell, PowerShell download-and-execute, recursive force delete, decode-and-execute, reverse shells |
| MCP005 | high | Credential file paths: SSH keys, cloud CLI credential files, browser login stores |
| MCP006 | medium | Large base64 blob |
| MCP007 | high/critical | Hardcoded secret (masked) |
| MCP008 | low–high | Unpinned / moving-tag package |
| MCP009 | info/high | Plain-HTTP transport (info for localhost) |
| MCP010 | medium/high | Broad filesystem root or sensitive docker mount |
| MCP011/012 | high/medium | Policy deny / not on allow list |
| MCP013–016 | varies | `--online` liveness: deprecated, stale, archived, missing package |
| MCP017 | low | Config parse error |
| MCP018 | info | SKILL.md missing frontmatter |
