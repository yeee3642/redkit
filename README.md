# redkit

**A portable, offline, no-AI red team toolkit.**

`redkit` is a self-contained command-line toolkit for authorized red team
engagements and CTF competitions. It is built around three hard constraints:

- **No AI.** redkit makes **zero** calls to any AI/LLM service. Every module is
  deterministic and rule-based. Nothing "phones home." This is by design so it
  can be used where AI assistance is disallowed (e.g. certain competitions) or
  where there is simply no internet.
- **Offline-first.** Wordlists and a default-credential database are bundled.
  redkit runs fully air-gapped with nothing but a Python interpreter.
- **Portable.** Pure Python standard library at its core — no mandatory
  third-party packages. Clone it to a USB stick, drop it on the range laptop
  (Windows *or* Linux), and run it.

> ⚠️ **Authorized use only.** redkit is for penetration testing, CTF, and
> security research **on systems you own or are explicitly authorized to test**.
> You are responsible for staying within scope and the law. See
> [Legal & scope](#legal--scope).

---

## Install

redkit needs **Python 3.8+** and nothing else to run.

```bash
git clone <your-repo-url> redkit
cd redkit

# Option A: just run it in place
python -m redkit --help

# Option B: install as the `redkit` command
pip install .
redkit --help
```

Optional extras enrich a few modules but are never required — each has a
pure-stdlib fallback:

```bash
pip install .[extra]     # paramiko (SSH), requests (HTTP)
```

When redkit wraps external tools (`nmap`, `hydra`, `netexec`, `smbclient`,
`dig`, ...) it auto-detects them and falls back to a built-in method or prints
what to install if they're absent.

---

## Concepts

**Engagement** — a workspace that stores everything you discover (hosts,
services, credentials, findings, loot, notes) as a single `engagement.json`.
Select one with `-e <name>` (default: `default`). Data lives under
`~/.redkit/engagements/<name>/` (override with the `REDKIT_HOME` env var).

**Module** — one capability (a scanner, a sprayer, a payload generator, ...).
Every module has a dotted `name` (`recon.port_scan`), belongs to a **phase**,
and declares its **options**. Modules read from and write to the shared
engagement, so recon feeds access feeds the report automatically.

**Phases** — the kill chain: `recon → access → postex → lateral → payloads →
report`.

---

## Quick start

```bash
# See everything available
python -m redkit list

# Learn a module's options
python -m redkit info recon.port_scan

# Recon: scan a host (results saved to the engagement)
python -m redkit -e op-acme run recon.port_scan -o target=10.10.10.5 -o ports=top

# Discover live hosts on a subnet
python -m redkit -e op-acme run recon.host_discovery -o target=10.10.10.0/24

# Web enumeration
python -m redkit -e op-acme run recon.web_enum -o url=http://10.10.10.5

# Access: check bundled default creds against discovered services
python -m redkit -e op-acme run access.default_creds -o test=true

# Payloads: generate reverse shells (offline; nothing is executed)
python -m redkit run payloads.revshell -o lhost=10.10.14.7 -o lport=443 -o shell=all

# Catch the shell
python -m redkit run payloads.listener -o lport=443

# Roll it all up into a report
python -m redkit -e op-acme report
```

Prefer a menu? Launch the interactive shell:

```bash
python -m redkit -e op-acme shell
# redkit> use recon.port_scan
# redkit(recon.port_scan)> set target 10.10.10.5
# redkit(recon.port_scan)> run
```

Global flags: `-e/--engagement <name>`, `-v/--verbose`, `--dry-run`
(print external commands without executing them).

---

## Module catalog

### recon
| module | what it does |
| --- | --- |
| `recon.port_scan` | Threaded TCP connect scan (+ optional `nmap`), banner grab, service ID |
| `recon.host_discovery` | Live-host sweep over CIDR/range via TCP-ping, ICMP, or ARP |
| `recon.web_enum` | HTTP fingerprint, security-header audit, robots/sitemap, directory brute |
| `recon.dns_enum` | DNS records, subdomain brute force, zone-transfer (AXFR) check |

### access
| module | what it does |
| --- | --- |
| `access.default_creds` | Match discovered services against a bundled default-credential DB (optional live check) |
| `access.cred_spray` | Lockout-aware password spraying (SSH/FTP/HTTP/SMB), wraps `hydra`/`netexec` or pure-python |

### postex
| module | what it does |
| --- | --- |
| `postex.linux_enum` | Linux privesc enumeration (SUID, sudo, cron, caps, ...) or offline checklist |
| `postex.windows_enum` | Windows privesc enumeration (privileges, unquoted paths, AlwaysInstallElevated, ...) or offline checklist |

### lateral
| module | what it does |
| --- | --- |
| `lateral.smb` | SMB enum / share listing / command exec, wraps `netexec`/`crackmapexec`/impacket/`smbclient` (pass-the-hash aware) |
| `lateral.winrm` | WinRM reachability + command exec via `netexec`/`evil-winrm`/`pywinrm` |

### payloads
| module | what it does |
| --- | --- |
| `payloads.revshell` | Reverse/bind shell one-liner generator (many shells; url/base64/ps-b64 encoding) |
| `payloads.listener` | Pure-python TCP handler to catch a shell, with PTY-upgrade hints and session logging |

### report
| module | what it does |
| --- | --- |
| `report.markdown` | Build a Markdown (or JSON) report from the engagement state |

---

## Adding a module

Drop a `.py` file into the matching `redkit/modules/<phase>/` directory — it is
auto-discovered, no wiring needed:

```python
from redkit.core.module import Module, Option, Result
from redkit.core.registry import register

@register
class MyThing(Module):
    name = "recon.my_thing"
    description = "does a useful recon thing"
    phase = "recon"
    options = [Option("target", required=True, help="host to poke")]

    def run(self, opts, ctx) -> Result:
        target = opts["target"]
        ctx.console.info(f"poking {target}")
        ctx.engagement.add_host(target)
        return Result(ok=True, summary=f"poked {target}")
```

The `ctx` object gives you `ctx.console`, `ctx.runner` (subprocess + tool
detection), `ctx.engagement` (shared state), and `ctx.workdir`. See
`redkit/core/` for the full API. **Keep it deterministic and AI-free.**

---

## Legal & scope

redkit is a security-testing tool. Use it **only** against systems you own or
have **explicit written authorization** to assess (a signed engagement, a CTF
you're registered for, your own lab). Unauthorized scanning, credential
attacks, or exploitation may be illegal. The authors provide this software
"as is" with no warranty and accept no liability for misuse. Stay in scope.

MIT licensed — see [LICENSE](LICENSE).
