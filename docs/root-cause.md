# Root Cause Analysis

Reconstruction of the `tfa-challenge` authentication bypass in Proxmox VE
7.0.0 – 8.0.3, derived from the fix in `libpve-access-control` 8.0.4.

## How the analysis was performed

The login endpoint (`POST /api2/json/access/ticket`) was reviewed by grepping
the extracted ISO packages for the endpoint path. This points to
`PVE/API2/AccessControl.pm`, and from there to `create_ticket_do` and the TFA
helpers it calls (`authenticate_user`, `authenticate_2nd_new`,
`user_get_tfa`). `AccessControl.pm` was pulled from every release from 7.0
through 9.1.1 and diffed across versions. The ticket-creation code is
structurally identical in every version except for one guard in
`user_get_tfa`.

The changelog for 8.0.4 confirmed the change:

```
libpve-access-control (8.0.4) bookworm; urgency=medium

  * Lookup of second factors is no longer tied to the 'keys' field in the
    user.cfg. This fixes an issue where certain LDAP/AD sync job settings
    could disable user-configured 2nd factors.

  * Existing-but-disabled TFA factors can no longer circumvent realm-mandated
    TFA.

 -- Proxmox Support Team <support@proxmox.com>  Thu, 20 Jul 2023 10:59:21 +0200
```

Both statements are true, but neither communicates that the change closed an
unauthenticated path to a root-equivalent ticket. No CVE was assigned and no
security advisory was published. That is the disclosure gap: the fix is
documented, but its security significance is not.

## The chain

The bypass is a chain of three weaknesses in the ticket-creation flow:

> `tfa-challenge` supplied → password check skipped → no TFA config returned →
> challenge verification skipped → full ticket issued

### Step 1: `tfa-challenge` skips password verification

When the `tfa-challenge` parameter is set, `create_ticket_do` skips
`verify_ticket()` and calls `authenticate_user()` with the challenge. Inside
`authenticate_user`, the presence of `tfa_challenge` routes execution into the
"2nd factor" branch, which never calls the realm plugin's password check:

```perl
# PVE/API2/AccessControl.pm:149 (create_ticket_do)
if (!defined($tfa_challenge)) {
    # We only verify this ticket if we're not responding to a TFA challenge, as in that case
    # it is a TFA-data ticket and will be verified by `authenticate_user`.
    ($ticketuser, undef, $tfa_info) = PVE::AccessControl::verify_ticket($pw_or_ticket, 1);
}
...
} else {
    ($username, $tfa_info) = PVE::AccessControl::authenticate_user(
        $username, $pw_or_ticket, $otp, $tfa_challenge,
    );
}
```

```perl
# PVE/AccessControl.pm:739 (authenticate_user)
if ($tfa_challenge) {
    # This is the 2nd factor, use the password for the OTP response.
    my $tfa_challenge = authenticate_2nd_new($username, $realm, $password, $tfa_challenge);
    return wantarray ? ($username, $tfa_challenge) : $username;
}

$plugin->authenticate_user($cfg, $realm, $ruid, $password);  # <-- never reached
```

### Step 2: `user_get_tfa` returns `undef` for users without a `keys` field

For users without a `keys` field in `user.cfg` (the default for `root@pam` and
all LDAP/AD-synced users) and a realm without a `tfa` setting, `user_get_tfa`
returned early:

```perl
# PVE/AccessControl.pm:2001 (user_get_tfa)
if (!$keys) {
    return if !$realm_tfa;
    die "missing required 2nd keys\n";
}
```

### Step 3: `authenticate_2nd_new` short-circuits without verifying the challenge

The `undef` from step 2 hit an early return in `authenticate_2nd_new_do`:

```perl
# PVE/AccessControl.pm:756 (authenticate_2nd_new_do)
if (!defined($tfa_cfg)) {
    return undef;   # <-- attacker's tfa-challenge is never verified
}
...
$tfa_challenge = verify_ticket($tfa_challenge, 0, $username);  # <-- unreachable (line 803)
```

The attacker-supplied `tfa-challenge` is only verified after this early return,
so any non-empty value passes. `authenticate_user` returns `($username, undef)`,
`create_ticket_do` sees no TFA info, and a full `root@pam` ticket is minted.

## Reproduction

The bypass was confirmed against an ephemeral PVE 7 laboratory (Debian 11,
pveproxy bound to localhost, reached over an SSH tunnel). A single request to
the ticket creation endpoint with a `tfa-challenge` parameter returned `200 OK`
with a full-access `root@pam` ticket:

```json
{"data":{"cap":{"nodes":{"Sys.Syslog":1,"Permissions.Modify":1,"Sys.Audit":1,"Sys.Console":1,"Sys.Incoming":1,"Sys.PowerMgmt":1,"Sys.Modify":1},"access":{"User.Modify":1,"Group.Allocate":1,"Permissions.Modify":1},"vms":{"Permissions.Modify":1,"VM.Snapshot":1,"VM.Snapshot.Rollback":1,"VM.Migrate":1,"VM.Monitor":1,"VM.Console":1,"VM.Config.Options":1,"VM.Config.Disk":1,"VM.Config.Memory":1,"VM.Audit":1,"VM.Config.Network":1,"VM.Clone":1,"VM.Backup":1,"VM.PowerMgmt":1,"VM.Config.Cloudinit":1,"VM.Allocate":1,"VM.Config.CPU":1,"VM.Config.CDROM":1,"VM.Config.HWType":1},"storage":{"Permissions.Modify":1,"Datastore.Audit":1,"Datastore.AllocateTemplate":1,"Datastore.Allocate":1,"Datastore.AllocateSpace":1},"dc":{"SDN.Use":1,"SDN.Allocate":1,"Sys.Audit":1,"SDN.Audit":1},"sdn":{"SDN.Allocate":1,"SDN.Use":1,"SDN.Audit":1,"Permissions.Modify":1}},"ticket":"PVE:root@pam:6A9495E3::<redacted>","CSRFPreventionToken":"6A9495E3:<redacted>","username":"root@pam"}}
```

The response includes the full `cap` map of root privileges, a valid `root@pam`
ticket, and a CSRF prevention token, all minted without a valid password. The
ticket is a full-access ticket, not a half-authenticated TFA ticket, so it can
be used directly against any API endpoint, including
`POST /nodes/<node>/terminal` for a root shell.

The same request against a patched system (8.0.4+ or any 9.x) returns
`401 authentication failure`.

## The fix

The complete fix is a 13-line change, three hunks in `AccessControl.pm`
(also available as a standalone patch in `patches/`):

```diff
@@ -753,6 +753,9 @@
     my ($username, $realm, $tfa_response, $tfa_challenge) = @_;
     my ($tfa_cfg, $realm_tfa) = user_get_tfa($username, $realm);

+    # FIXME: `$tfa_cfg` is now usually never undef - use cheap check for
+    # whether the user has *any* entries here instead whe it is available in
+    # pve-rs
     if (!defined($tfa_cfg)) {
        return undef;
     }
@@ -805,6 +808,10 @@
        $tfa_challenge = undef;
     } else {
        $tfa_challenge = $tfa_cfg->authentication_challenge($username);
+
+       die "missing required 2nd keys\n"
+           if $realm_tfa && !defined($tfa_challenge);
+
        if (defined($tfa_response)) {
            if (defined($tfa_challenge)) {
                $tfa_done = 1;
@@ -1998,15 +2005,11 @@
     $realm_tfa = PVE::Auth::Plugin::parse_tfa_config($realm_tfa)
        if $realm_tfa;

-    if (!$keys) {
-       return if !$realm_tfa;
-       die "missing required 2nd keys\n";
-    }
-
     my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
     if (defined($keys) && $keys !~ /^x(?:!.*)$/) {
        add_old_keys_to_realm_tfa($username, $tfa_cfg, $realm_tfa, $keys);
     }
+
     return ($tfa_cfg, $realm_tfa);
 }
```

- **Hunk 3 closes the bypass.** The `!$keys` early-return was removed from
  `user_get_tfa`, so the real `priv/tfa.cfg` object is always returned and the
  code falls through to `verify_ticket($tfa_challenge, 0, $username)`, which
  rejects any non-signed value.
- **Hunk 2** adds a guard so a missing challenge is rejected when the realm
  mandates TFA.
- **Hunk 1** is a FIXME comment; the developers note that `$tfa_cfg` is now
  "usually never undef" — exactly why the short-circuit that made this bypass
  possible is unreachable.

## Disclosure analysis

PSA-2026-00043-1 (2026-09-01) resolved the open questions:

- The 8.0.4 change was not a security fix: the vulnerable code path was closed
  "as a side effect of a rework of the TFA configuration handling for an
  unrelated issue," and the authentication bypass "was not known: ... had
  neither been found internally nor reported."
- The issue was therefore not recognized as a candidate for a backport to the
  PVE 7 branch, leaving the EOL releases vulnerable.
- Exploitation in the wild was reported, and the advisory ships an official
  stop-gap mitigation for affected EOL installations.

Prior to the advisory, the two readings could not be separated on the public
record. The advisory's account matches the "unrecognized" explanation: the fix
was never deliberately silent, but the disclosure gap — no CVE, no advisory,
EOL releases left exposed for three years — stands regardless of intent.

### Why PVE 6 is not affected

PVE 6 (libpve-access-control 6.4-3, pulled from the Proxmox archive) has no
`tfa-challenge` parameter at all, and its `authenticate_user` calls the realm
plugin's password check unconditionally before any TFA logic. The bypass cannot
exist there.

### Why 9.x is not affected

In 9.x the TFA logic lives in Rust, compiled into `libpve_rs.so`; the binding
source from the proxmox-perl-rs repository shows `Tfa::new()` always returns a
valid config object, `authentication_challenge` returns `None` when no second
factor is configured, and `authentication_verify2` returns `result: false` on
any failed verification. There is no path where a forged challenge skips
verification. `AccessControl.pm` extracted from the PVE 9.2 ISO is
byte-identical (same MD5) to the 9.1.1 .deb; pve-manager 9.2.2 vs 9.2.9 vs
9.2.11 differ only in Ceph, APT, and subscription changes. No auth changes.
