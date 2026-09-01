# Detection

Four experimental Sigma rules for the `tfa-challenge` authentication bypass in
Proxmox VE 7.0.0 – 8.0.3. All rules assume a log source mapped to the
`proxmox` product tag in your SIEM.

**Treat these as hunting signals, not proof:** a 200 on the ticket endpoint
from an unexpected IP is a strong lead, but legitimate logins from
non-whitelisted networks produce the same response.

| Rule | File | Signal | Level |
|---|---|---|---|
| Probe detection | `01-access-ticket-endpoint-probe.yml` | >5 POSTs to `/api2/json/access/ticket` from one IP in 5m; a burst of 308/401 responses is the signature of probing, including re-probing of patched systems | medium |
| Possible exploitation | `02-successful-ticket-unexpected-source.yml` | HTTP 200 on the ticket endpoint from a source outside admin networks; on vulnerable systems the bypass mints a full `root@pam` ticket and returns 200 with no valid password | high |
| Post-auth signal | `03-successful-root-pam-auth.yml` | pveproxy syslog `successful auth for user 'root@pam'` with no preceding failed attempt from the same source | medium |
| Failed attempt burst | `04-auth-failure-burst.yml` | >10 `authentication failure` messages from one source in 5m; the patched code path rejects the forged `tfa-challenge` with 401 | medium |

## Notes

- **Rule 02:** Whitelist your admin ranges in `filter_known_admin` (the
  placeholder RFC1918 ranges assume an RFC1918-only admin network) and
  correlate with rule 03. Legitimate logins from non-whitelisted networks look
  identical to exploitation.
- **Rule 04:** A burst of 401s on the ticket endpoint also matches re-probing
  of patched systems and brute-force attempts against valid accounts.
