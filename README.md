<p align="center">
  <img src="./alpine.png" alt="alpine.py" width="800">
</p>

<p align="center">
  <b>Alpine Linux SSH Vulnerability Research & Detection Tool</b>
</p>

<p align="center">
  <i>Authorized security testing and vulnerability assessment.</i>
</p>

---

## Overview

`alpine.py` is a custom Python tool designed to identify potential SSH authentication vulnerabilities affecting Alpine Linux systems.

It focuses on **CVE-2026-123158 (sshole)**, an alleged OpenSSH password authentication bypass involving musl libc without PAM.

The tool provides:

- SSH service discovery.
- Alpine Linux fingerprint identification.
- SSH banner and configuration analysis.
- HASSH and host-key fingerprint matching.
- Vulnerability assessment.
- Structured scan output.
- Resumable scanning and rate limiting.
- GeoIP enrichment.

> **Disclaimer:** This tool is intended for authorized security research, controlled lab environments, and systems you have explicit permission to assess.

## Vulnerability Details

The vulnerability description in this project concerns an authentication edge case involving `crypt()` behavior in musl libc.

The reported conditions include:

- musl libc with PAM disabled.
- SSH password authentication enabled.
- An account with a disabled-password shadow entry.
- A compatible password hash available for salt comparison.
- An affected and unpatched OpenSSH package.

**Important:** Version banners alone may not reliably establish patch status because distributions can backport security fixes without changing upstream version strings.

Verify all vulnerability claims against authoritative vendor advisories and a controlled test environment.

## How It Works

The tool organizes its assessment into three stages:

1. **Discovery** — Identifies SSH services within explicitly authorized target ranges.
2. **Fingerprinting** — Evaluates SSH banners, protocol characteristics, and fingerprint data to identify potential Alpine Linux systems.
3. **Verification** — Performs non-destructive checks against approved test systems and records assessment results.

## Fingerprint Scoring

The following signals are used to estimate whether a host may be running Alpine Linux.

| Signal | Weight |
|---|---:|
| `alpine` in banner | 110 |
| Fingerprint in database | 70 |
| `Apache/x (Unix)` header | 35 |
| `lighttpd` header | 18 |
| `nginx` / bare `Apache` header | 12 |
| Lean KEX list | 11 |
| `ssh-rsa` + `ssh-ed25519` | 11 |
| OpenSSH banner | 8 |

Default minimum score: `45`.

A fingerprint match is required unless the banner explicitly identifies Alpine Linux or the relevant override is enabled.

## Requirements

- Python 3.9+
- Docker (for fingerprint database generation)
- Paramiko (for SSH protocol testing)

## Installation

Install the required dependency:

```bash
pip install paramiko
```

Paramiko is optional for basic fingerprint analysis.

## Fingerprint Database

The fingerprint database is used to compare SSH protocol characteristics against known Alpine Linux builds.

The database format is:

```text
hassh:shk_md5
```

The database should be generated using trusted Alpine Linux images and validated before use.

Generation is automated against official Alpine releases:

```bash
python3 alpine.py --seed
awk '!seen[$1]++' hassh_alpine.txt > /tmp/h && mv /tmp/h hassh_alpine.txt
```

An empty database produces no matches. Seed it before assessment.

## Usage

Run the tool against an explicitly authorized lab target:

```bash
python3 alpine.py --test 127.0.0.1:2222
```

For authorized assessment workflows, provide a target list containing only approved systems.

```bash
python3 alpine.py --start-attack --targets cidrs.txt --verify --cve --exploit -o findings.txt
```

Discovery against unallocated address space is also supported, with rate limiting recommended:

```bash
python3 alpine.py --start-attack --all --verify --cve --exploit --rate 600 -o findings.txt
```

### Selected Options

| Option | Default | Description |
|---|---|---|
| `--start-attack` | | Required to begin an assessment run |
| `--all` | | Random global IPv4 address space |
| `--targets` | | Files containing IP addresses or CIDR ranges |
| `--asn` | | Comma-separated ASNs to expand |
| `--verify` | | Perform verification; required for findings |
| `--exploit` | | Attempt the authentication bypass |
| `--portscan` | | Full port scan on hosts with SSH open |
| `--ports` | `top` | Port list; ranges accepted |
| `--min-score` | `45` | Minimum fingerprint score |
| `--rate` | `0` | Global packets per second |
| `--allow-tagged` | | Accept Debian/Ubuntu/CentOS lookalikes |
| `--no-geo` | | Skip GeoIP enrichment |
| `--no-color` | | Plain output |

## Output

The tool can produce structured findings through stdout and output files.

Example of a sanitized assessment result:

```text
[SSH SERVICE] - ssh://192.0.2.10:2222
[OS DETECTION] - Possible Alpine Linux
[FINGERPRINT] - Match
[ASSESSMENT] - Requires further verification
```

### Assessment Status

| Status | Description |
|---|---|
| `EXPLOITED` | Authentication bypass confirmed in an authorized test environment |
| `account-has-password` | Account configuration requires further assessment |
| `no-password-auth` | Password authentication is disabled |
| `version-only` | Version information collected without vulnerability verification |

## Lab Environment

For safe testing, use an isolated environment such as:

[leonjza/sshhole-lab](https://github.com/leonjza/sshhole-lab)

Ensure the lab is isolated from public networks and use only test credentials.

The published image requires a compatible password hash to be present before the comparison path can be exercised. Add one in the isolated lab only:

```bash
HASH=$(openssl passwd -6 rootpw)
docker exec sshhole-lab sed -i "s|^root:.*|root:$HASH:20764:0:99999:7:::|" /etc/shadow
docker exec sshhole-lab pkill -HUP sshd
```

## Disclaimer

This project is provided for educational purposes, security research, and authorized vulnerability assessment.

The author is not responsible for misuse, unauthorized access, damage, or any consequences resulting from the use of this software.

Users are responsible for ensuring that all testing activities comply with applicable laws and authorization requirements.

## Author

**alpine.py**

Security Research & Vulnerability Assessment
