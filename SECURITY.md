# Security boundaries

- Rejects absolute/traversing paths, backslashes, drive/ADS syntax, control
  characters, DOS device names, trailing dots/spaces, and duplicate, case or
  Unicode-normalized collisions (including ambiguous parent directories).
- Rejects file/directory conflicts, symlink/special ZIP entries, Windows reparse
  attributes and symlink/reparse/special source tree entries. ZIP extra fields
  are never interpreted as links. Extraction does not call extractall.
- Bounds central-directory allocation before ZipFile reads it; caps entry count,
  expanded size and compression ratio; streams files and verifies ZIP CRCs.
  Memory is still proportional to allowed central-directory size and path count.
  CRC is corruption detection, not authentication.
- Uses temporary staging, exclusive file creation and no overwrite by default.
  File publication uses an atomic hardlink on filesystems supporting it, with an
  exclusive-copy fallback. The fallback may briefly expose an incomplete output
  and removes it on failure. Extraction publishes a completed directory by rename.
- Removes privileged permission bits and restores safe execute permissions.
  ZIP timestamps, custom permission metadata and archive comments are not preserved.
- Never executes IPA binaries or shell text. zsign is an explicit trusted external
  executable. Native `.exe` is required on Windows; `.cmd`/`.bat` signers are rejected.
- Terminal output escapes metadata to prevent escape-sequence injection.

This is defensive archive handling, **not a hostile multi-user filesystem sandbox**.
Use stable input files and trusted parent directories on a local filesystem. A
concurrent attacker who can rename ancestors, mount filesystems, modify sources or
replace output directories may defeat pathname-based checks. Do not run elevated.
Memory/disk/CPU quotas must be imposed externally for a service handling untrusted
uploads. Process termination kills the direct signer, not an arbitrary child tree.

Keep signing keys outside the source tree. Temporary extraction contains private
app data and is removed after normal operation; termination/power loss can leave
temporary files. Standard deletion is not secure erasure.

Passwords are not printed or placed in reports. Upstream zsign's password API uses
`-p`, so the password can be visible to local process inspection while it runs.
The default `ANY2IPA_P12_PASSWORD` variable is removed from the child's environment.
If using a differently named password variable, it is inherited by the signer.
Environment variables themselves are not a secret vault. Use an isolated trusted
machine/account for sensitive identities.

Neither signatures, certificate chains, revocation, profile CMS authenticity,
provisioned devices, DRM state, entitlement compatibility nor Apple policy are
cryptographically verified by Any2IPA. Do not infer installability from inspection
or the existence of signature files. No security audit is claimed.
