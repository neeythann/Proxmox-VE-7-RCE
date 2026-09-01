# Proxmox VE 7.x/8.0.x Authentication Bypass (tfa-challenge)

Research repository reconstructing an unauthenticated authentication bypass in
Proxmox VE 7.0.0 through 8.0.3 that mints a full `root@pam` ticket with a single
HTTP request and no valid password.

> **DISCLAIMER:** This research did not discover the vulnerability. Proxmox
> fixed the underlying bug on 2023-07-20 in `libpve-access-control` 8.0.4. This
> repository analyzes that fix and reconstructs the resulting authentication
> bypass so that operators of affected (including now-EOL) systems can
> understand what changed and why the issue was security-relevant.
>
> [PSA-2026-00043-1](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/post-867929)
> (2026-09-01) confirmed that the 8.0.4 change was not a security fix: the
> vulnerable code path was closed as a side effect of a TFA configuration
> rework for an unrelated issue, at which time the bypass was not known. The
> issue was consequently not backported to the PVE 7 branch. Exploitation in
> the wild has been reported; the advisory includes an official stop-gap
> mitigation for affected EOL installations.

## TL;DR

- **Impact:** Unauthenticated full `root@pam` ticket, no valid password required
- **CVSS v3.1:** 9.8 (Critical) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Affected:** Proxmox VE 7.0.0 – 8.0.3 (`libpve-access-control <= 8.0.3`)
- **Fixed:** `libpve-access-control >= 8.0.4` (2023-07-20)
- **CVE:** none assigned — this is the disclosure gap
- **Exploit:** single HTTP request, no interaction, default installations affected

## The bug

On a vulnerable system a single request to the ticket creation endpoint
returns `200 OK` with a valid full-access `root@pam` ticket and a CSRF
prevention token, without a valid password. The same request against a patched
system (8.0.4+) returns `401 authentication failure`.

## Root cause (one line)

`tfa-challenge` supplied → password check skipped → no TFA config returned →
challenge verification skipped → full ticket issued.

Three weaknesses chain together in the ticket-creation flow
(`PVE/API2/AccessControl.pm` + `PVE/AccessControl.pm`):

1. **`tfa-challenge` skips password verification** — `create_ticket_do`
   routes into the "2nd factor" branch of `authenticate_user`, which never
   calls the realm plugin's password check.
2. **`user_get_tfa` returns `undef` for users without a `keys` field** — the
   default for `root@pam` and LDAP/AD-synced users.
3. **`authenticate_2nd_new_do` short-circuits** — the `undef` TFA config hits
   an early return before `verify_ticket()` ever runs; any non-empty
   `tfa-challenge` passes.

Full analysis: [docs/root-cause.md](docs/root-cause.md)

## Repository layout

```
├── README.md                  # this overview
├── docs/
│   ├── root-cause.md          # full root cause chain + fix diff analysis
│   └── timeline.md            # disclosure timeline
├── detection/                 # Sigma rules for pveproxy access log / syslog
│   ├── 01-access-ticket-endpoint-probe.yml
│   ├── 02-successful-ticket-unexpected-source.yml
│   ├── 03-successful-root-pam-auth.yml
│   └── 04-auth-failure-burst.yml
├── patches/
│   ├── libpve-access-control-8.0.4.diff  # the fix, as a unified diff
│   └── PSA-2026-00043-1-stop-gap.diff    # official advisory mitigation (EOL systems)
```

## Detection

The `detection/` directory contains four experimental Sigma rules mapped to the
`proxmox` product tag. Treat them as hunting signals, not proof: a 200 on the
ticket endpoint from an unexpected IP is a strong lead, but legitimate logins
from non-whitelisted networks produce the same response. See
[detection/README.md](detection/README.md).

## Affected versions

Per PSA-2026-00043-1: affected is `libpve-access-control >= 7.0-7 and < 8.0.4`,
roughly corresponding to PVE 7.0 up to and including 7.4 (EOL since 2024-07),
plus initial PVE 8.0 (EOL). Package versions and overall PVE versions only
correlate loosely — **check the installed package version, not the PVE version**:

```sh
dpkg-query -W -f '${Version}\n' libpve-access-control
# or: pveversion -v
```

| Component | Affected | Fixed |
|---|---|---|
| libpve-access-control | `>= 7.0-7, < 8.0.4` | `>= 8.0.4` (released 2023-07-20) |

- PVE 6 is **not** affected (no `tfa-challenge` parameter exists; the password
  check is unconditional).
- PVE 8.0.4+ and 9.x are **not** affected. In 9.x the TFA logic lives in Rust
  (`libpve_rs.so`); `Tfa::new()` always returns a valid config object and there
  is no path where a forged challenge skips verification.
- **Default installations are affected:** `root@pam` has no `keys` field by
  default, so no special configuration is required. Users with any second
  factor configured for login are not affected.

Verified against extracted package sources for libpve-access-control 7.0-7,
7.4.3, 8.0.1, 8.0.3 (vulnerable) and 8.0.4, 8.0.5, 8.0.6, 8.0.7, 8.1.0,
8.1.4, 8.2.3, 9.1.1 (patched), plus the PVE 9.2 ISO (byte-identical
`AccessControl.pm` vs the 9.1.1 .deb).

## Remediation

1. **Upgrade** to a supported release (PVE 8.1+ or 9.x) — the only durable
   fix, per the advisory. Affected releases are EOL and have not received
   security fixes for the PVE stack, kernel, QEMU, or LXC.
2. **Stop-gap patch for EOL systems that cannot upgrade immediately** — the
   official PSA-2026-00043-1 mitigation adds a validation step so every
   `tfa-challenge` value must be a valid signed TFA challenge ticket:

   ```sh
   sed -i.bck 's/^\t# This is the 2nd factor, use the password for the OTP response.$/\tverify_ticket($tfa_challenge, 0, $username);\n\t# This is the 2nd factor, use the password for the OTP response./' /usr/share/perl5/PVE/AccessControl.pm

   grep -n 'verify_ticket($tfa_challenge, 0, $username)' /usr/share/perl5/PVE/AccessControl.pm | wc -l

   systemctl reload-or-restart pvedaemon pveproxy
   ```

   The grep must print `3`. If it prints anything else the patch did not
   apply and the installation is still vulnerable. To undo, restore the
   `.bck` backup and restart both services. The same mitigation as a unified
   diff: [patches/PSA-2026-00043-1-stop-gap.diff](patches/PSA-2026-00043-1-stop-gap.diff).
3. **Restrict API access.** Installations whose API is not reachable by
   potential attackers are not exposed; restricting API access to trusted
   networks has always been Proxmox's recommended setup. Bind pveproxy to
   localhost (`LISTEN_IP="127.0.0.1"` in `/etc/default/pveproxy`, then restart
   pveproxy) and reach it over an SSH tunnel or VPN.
4. **Monitor** pveproxy access logs for `POST /api2/json/access/ticket`
   requests containing a `tfa-challenge` parameter, and for successful ticket
   responses (`200`) not preceded by a valid login flow (see `detection/`).

## Disclosure

Full timeline: [docs/timeline.md](docs/timeline.md)

This repository's author was one of the independent reporters credited in
[PSA-2026-00043-1](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/post-867929)
(*Nathan Xavier Golez*), having independently
reproduced the bypass, analyzed the fix, and reported it to Proxmox before
the advisory.

| Date (EDT) | Event |
|---|---|
| 2021-07 | `tfa-challenge` parameter introduced with PVE 7.0 |
| 2023-07-20 | Fix released in `libpve-access-control` 8.0.4 without a CVE or security advisory |
| 2026-08-29 | Investigation begins |
| 2026-08-30 | Bypass confirmed via patch diffing; PGP-encrypted reports submitted to Proxmox |
| 2026-08-31 | Proxmox confirms PVE 7 affected; discloses an independent report received ~1 day earlier |
| 2026-09-01 | Formal advisory released: [PSA-2026-00043-1](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/post-867929); fix confirmed to have been an unrecognized side effect, exploitation in the wild reported |
