# secrex

![secrex TUI](demo.jpg)

A small, dependency-free per-user secret manager for PowerShell — now cross-platform. Secret *names* live in a single JSON file; secret *values* are encrypted with the strongest thing each OS gives you:

| OS | Backend | Where values live |
| --- | --- | --- |
| Windows | DPAPI (`ConvertFrom-SecureString`) | `%APPDATA%\secrex\store.json`, decryptable only by your Windows user |
| macOS | login Keychain (`security`) | Keychain items under service `secrex`; the JSON keeps names only |
| Linux | AES-256 (`ConvertFrom-SecureString -Key`) | `~/.config/secrex/store.json`, key file `~/.config/secrex/key` (chmod 600) |

- **Scopes:** personal (`~`), per-project (folder-based), and on macOS a Touch ID **vault**
- **One-file module:** `secrex.psm1` + `secrex.psd1`, works on Windows PowerShell 5.1 and PowerShell 7+
- **CLI aliases:** `g`, `s`, `a`, `ls`, `rm`, `i`
- **TUI:** running `secrex` with no arguments opens an interactive two-pane view — with peek, add, delete and a tiny intro animation
- **`.env` in and out:** `secrex import .env myapp`, `secrex export myapp .env.local`
- **Wildcards in `get`:** `secrex g 'bri*'`, `secrex g 'myapp/*'`, `secrex g '/token'`
- **Claude Code skill** included — let the agent fetch keys instead of pasting them into chat

## Install

**Windows**

```powershell
git clone https://github.com/nik-devs/secrex-cli.git D:\Tools\secrex
Import-Module D:\Tools\secrex\secrex.psd1
```

**macOS / Linux** — needs PowerShell 7 (`brew install --cask powershell@preview` or the [official packages](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)):

```powershell
git clone https://github.com/nik-devs/secrex-cli.git ~/dev/secrex
Import-Module ~/dev/secrex/secrex.psd1
```

To have it available in every PowerShell session, append the import line to your `$PROFILE`:

```powershell
if (-not (Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force | Out-Null }
Add-Content -Path $PROFILE -Value "`nImport-Module ~/dev/secrex/secrex.psd1"
```

> Windows PowerShell 5.1 and PowerShell 7 use **different** `$PROFILE` paths. Run the snippet in each host you care about.

If Windows PowerShell refuses to run the profile (`running scripts is disabled`), unblock user-scope scripts once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Quick start

```powershell
# register the current folder as a project (project name = folder name)
cd ~/dev/myapp
secrex init

# add secrets
secrex add openai                 # personal, interactive hidden prompt
secrex add myapp/github           # project-scoped, interactive
secrex add bright-data 1d045222   # inline value (goes into shell history)

# read secrets
secrex get openai                 # prints the value
secrex g  myapp/github -Copy      # copies to clipboard
$s = secrex g myapp/github -AsSecureString

# list
secrex ls                         # every secret
secrex ls ~                       # only personal
secrex ls projects                # registered projects + folder paths
secrex ls myapp                   # everything in project myapp
secrex ls /openai                 # all secrets named 'openai' across scopes

# delete
secrex rm myapp/github
```

## The Touch ID vault (macOS)

`vault` is a reserved scope whose secrets sit behind your fingerprint. Reading (or writing) anything in it pops the native Touch ID sheet first, with automatic fallback to the account password on Macs without a sensor:

```powershell
secrex add vault/prod-db          # touch the sensor, then type the value
secrex get vault/prod-db          # touch the sensor, get the value
secrex export vault prod.env      # one touch unlocks the whole command
```

No extra setup, no compiled helpers — the gate is a `LocalAuthentication` prompt driven through `osascript`, and the values live in your login Keychain under the separate service `secrex.vault`. Honest fine print: the biometric check is enforced by secrex itself (macOS only lets signed apps bind Keychain items to biometrics), so treat it as a strong "are you really there?" gate on top of Keychain storage, not hardware-bound encryption.

In the TUI the vault shows up as a pinned 🔒 entry in the projects pane.

## `.env` import / export

Move an existing project onto secrex in one line, and materialize env files back out when a tool insists on one:

```powershell
secrex import .env myapp          # every KEY=VALUE line becomes myapp/KEY
secrex import .env                # ...or into the personal scope
secrex export myapp .env.local    # scope -> file (chmod 600, plaintext!)
secrex export myapp               # scope -> stdout, so this works too:
secrex export myapp | pbcopy
```

The importer understands comments, `export KEY=...` prefixes, single/double quotes and `\n` escapes; the exporter quotes anything that needs it, so an export/import round-trip is lossless.

## TUI

Running `secrex` with no arguments opens an interactive view with two panes: **personal** and **projects** (see screenshot above).

| Key               | Action                                           |
| ----------------- | ------------------------------------------------ |
| `↑` / `↓`         | move inside the active pane                      |
| `Tab` / `←` / `→` | switch between panes                             |
| `Enter`           | copy value (secrets) / open (projects)           |
| `p`               | peek — flash the value on screen without copying |
| `a`               | add a secret in the current scope                |
| `d`               | delete the selected secret (asks `y/n`)          |
| `Esc`             | back from project view                           |
| `q`               | quit                                             |

There's a small intro animation on launch; set `SECREX_NO_ANIM=1` if you're not here to have fun. `SECREX_HOME` relocates the store (handy for tests and dotfile setups).

## Use with Claude Code

The repo ships a skill (`skills/secrex/SKILL.md`) that teaches Claude Code to look keys up with `secrex get` instead of asking you to paste them into the conversation, and to route `.env` requests through `import`/`export`. Install it by copying the folder:

```bash
# for you, in every project
cp -r skills/secrex ~/.claude/skills/

# or just for one project
cp -r skills/secrex /path/to/project/.claude/skills/
```

Restart Claude Code and it picks the skill up automatically whenever a task involves credentials. The skill also carries the safety rules: never echo values into the chat, prefer interactive `add`, warn before touching the vault.

## Commands

| Command   | Aliases         | What it does                                   |
| --------- | --------------- | ---------------------------------------------- |
| `init`    | `i`             | register current folder as a project           |
| `set`     | `s`, `add`, `a` | store a secret (prompts if value omitted)      |
| `get`     | `g`             | read a secret; supports wildcards              |
| `list`    | `ls`            | list secrets, filtered                         |
| `remove`  | `rm`            | delete a secret                                |
| `import`  | `imp`           | import a `.env` file into a scope              |
| `export`  | `exp`           | export a scope as `.env` (stdout or file)      |
| `version` |                 | print version                                  |
| `help`    | `-h`, `--help`  | show command reference                         |

## Path grammar

Secrets live at `<scope>/<name>`. `~` is the personal scope; `vault` is the Touch ID scope on macOS; anything else is a project name registered via `secrex init`.

| Path              | Meaning                                   |
| ----------------- | ----------------------------------------- |
| `openai`          | personal (same as `~/openai`)             |
| `~/openai`        | personal, explicit                        |
| `myapp/openai`    | project `myapp`                           |
| `vault/prod-db`   | Touch ID vault (macOS)                    |

`list` filters extend the grammar:

| Filter            | Meaning                                   |
| ----------------- | ----------------------------------------- |
| *(empty)*         | everything                                |
| `~`               | all personal                              |
| `projects`        | registered projects with folder paths     |
| `myapp` / `myapp/`| everything in project `myapp`             |
| `/openai`         | all secrets named `openai` across scopes  |

`get` additionally accepts PowerShell wildcards (`*`, `?`, `[...]`) in both the scope and the name:

| Pattern          | Matches                                            |
| ---------------- | -------------------------------------------------- |
| `bri*`           | personal secrets starting with `bri`               |
| `myapp/*`        | every secret in project `myapp`                    |
| `/bright-data`   | `bright-data` across every scope                   |
| `*/tok*`         | any scope, names starting with `tok`               |

On multiple matches, `get` returns `{Path, Value}` rows (format as a table). `-Copy` and `-AsSecureString` require an exact single match.

## Storage & security

- Store file: `%APPDATA%\secrex\store.json` on Windows, `~/.config/secrex/store.json` elsewhere (override with `SECREX_HOME`).
- Shape:
  ```json
  {
    "projects": { "myapp": { "path": "/Users/nik/dev/myapp" } },
    "secrets":  {
      "~":     { "openai": "<DPAPI blob (win) | keychain:1 (mac) | aes:... (linux)>" },
      "myapp": { "github": "..." },
      "vault": { "prod-db": "vault:1" }
    }
  }
  ```
- On Windows the file only decrypts for the same **Windows user** on the same **machine** — moving `store.json` to another user or host makes it unreadable, intentionally. Stores created with 0.1.0 keep working as-is.
- On macOS/Linux, secret values never touch `store.json` at all (macOS) or are AES-encrypted with a mode-600 key file (Linux).
- Passing values on the command line (`secrex add name value`) puts them into shell history. For sensitive secrets, use the interactive form (`secrex add name`), which prompts with a hidden `Read-Host -AsSecureString`.
- `export` writes plaintext by design (that is what `.env` files are); the file is `chmod 600` on Unix, but treat it like a loaded footgun anyway.

`secrex init` stores the project's folder path in the store so you know where a project lives; it does **not** implicitly scope commands by the current working directory — every `set` / `get` / `rm` requires an explicit path.

## License

MIT — see [LICENSE](LICENSE).
