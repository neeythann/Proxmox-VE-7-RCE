# Disclosure Timeline

All times in EDT.

| Date | Event |
|---|---|
| 2021-07 | `tfa-challenge` parameter introduced with PVE 7.0. |
| 2023-07-20 | Fix released in `libpve-access-control` 8.0.4 without a CVE or security advisory. |
| 2026-08-05 | A user posted in a forum regarding unusual authentication behavior. |
| 2026-08-29 12:01PM | Investigation of activity described in the forum post led to analysis of the Proxmox authentication issue. |
| 2026-08-30 2:30PM | Confirmed the API endpoint authentication bypass through patch diffing. |
| 2026-08-30 3:48PM | Submitted a PGP-encrypted vulnerability report through Proxmox's preferred security channel; this blog post published as draft. |
| 2026-08-30 4:48PM | Submitted another PGP-encrypted vulnerability report with steps to reproduce and a proof-of-concept exploit. |
| 2026-08-31 10:04AM | Proxmox Security Team confirmed that PVE 7 is affected and agreed with the initial affected-version analysis. Proxmox also disclosed that it had received an independent report concerning the same issue via unencrypted email approximately one day earlier. |
| 2026-08-31 11:17AM | Requested attribution in any resulting public disclosure or security advisory for the independent reproduction, analysis, and responsible reporting of the issue. |
| 2026-09-01 2:32AM | Formal advisory released: [PSA-2026-00043-1](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/post-867929). Proxmox confirmed the fix shipped as a side effect of a TFA rework for an unrelated issue — the bypass was not known at the time, and the change was not a security fix. Exploitation in the wild confirmed. |

## Post-advisory: disclosure questions resolved

PSA-2026-00043-1 settles the uncertainty described in this repository's
analysis:

- **"Unrecognized" vs "deliberately silent":** the advisory states the
  vulnerable code path was closed "as a side effect of a rework of the TFA
  configuration handling for an unrelated issue" and that "the authentication
  bypass was not known: the rework was not a security fix." Proxmox's public
  position is that the impact was unrecognized at fix time, not deliberately
  concealed. This matches the "unrecognized" reading described in
  [root-cause.md](root-cause.md).
- **Attribution:** the advisory lists this repository's author — Nathan
  Xavier Golez — as one of the independent reporters, alongside Kamil
  Rakowski and Sagnik Sasmal.
- **Scope:** affected is `libpve-access-control >= 7.0-7 and < 8.0.4`
  (PVE 7.0 through 7.4, EOL since 2024-07, plus initial PVE 8.0, EOL) — the
  advisory directs operators to check the installed package version rather
  than the PVE version.
- **Mitigation:** official stop-gap patch available for EOL systems; upgrade
  to a supported release is the only durable fix.
