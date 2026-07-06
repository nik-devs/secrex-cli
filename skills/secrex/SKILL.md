---
name: secrex
description: Read and store local secrets (API keys, tokens, passwords) with the secrex CLI instead of asking the user to paste them into chat. Use when a task needs an API key or credential, when the user asks to save/list/delete a secret, or to import/export .env files.
---

# secrex — local secret manager

secrex is a PowerShell module. Every command below runs through `pwsh` (or
`powershell` on Windows). If `secrex` is not on the profile, import it first:

```
pwsh -NoProfile -Command "Import-Module <repo>/secrex.psd1; secrex <args>"
```

If the module is imported in the user's profile, drop `-NoProfile`:

```
pwsh -Command "secrex get openai"
```

## When a task needs a credential

1. Look for it before asking the user: `secrex ls`, then `secrex ls <project>`
   for the current project (project name = folder name registered via
   `secrex init`).
2. Read it: `secrex get <scope>/<name>` prints the plaintext value to stdout.
   Capture it into an environment variable for the command that needs it —
   do not write it into files, code, or logs.
3. If it does not exist, ask the user to run `secrex add <scope>/<name>`
   themselves (interactive hidden prompt keeps the value out of the
   conversation), then read it back with `secrex get`.

## Command reference

| Command | Purpose |
| --- | --- |
| `secrex ls [filter]` | list secret paths (`~` personal, `projects`, `<proj>`, `/name`) |
| `secrex get <path>` | print value; wildcards allowed (`secrex get 'myapp/*'`) |
| `secrex get <path> -Copy` | copy to clipboard instead of printing |
| `secrex add <path> [value]` | store; omit value for interactive hidden prompt |
| `secrex rm <path>` | delete |
| `secrex init` | register the current folder as a project scope |
| `secrex import <file> [scope]` | import KEY=VALUE pairs from a .env file |
| `secrex export [scope] [file]` | export a scope as .env lines (stdout if no file) |

Paths are `scope/name`; a bare name means the personal scope `~`.

## Scopes

- `~` — personal secrets.
- `<project>` — per-project, registered with `secrex init` in the project folder.
- `vault` — macOS only, gated by Touch ID. Reading `vault/*` pops a system
  fingerprint prompt, so warn the user before running it and never use it in
  non-interactive scripts.

## Safety rules

- Never echo secret values into the conversation, commit them, or write them
  to files the user did not ask for. Prefer `$env:X = secrex get ...` /
  `X=$(pwsh -Command "secrex get ...")` inline.
- `secrex add <path> <value>` puts the value into shell history — prefer the
  interactive form and let the user type it.
- `secrex export <scope> <file>` writes plaintext (chmod 600). Only do it when
  the user explicitly asks, and remind them the file is unencrypted.
