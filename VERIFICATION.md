# Any2IPA 1.0.0 — delivery verification

Verified locally on **2026-11-04**, Windows, Python 3.14.5.

- Universal wheel built successfully and installed offline into a clean virtual environment.
- **22 automated tests passed**, with no skipped tests on this host.
- Tests cover XML/binary plist metadata, CRC failures, path traversal, Windows paths,
  duplicate/case/Unicode collisions, symlinks/special entries/reparse attributes,
  malformed ZIPs, encrypted/unsupported compression, resource limits, directory
  conflicts, no overwrite, standalone .app packaging, content round trips,
  reproducible packing and actual CLI subprocess execution.
- Signing success is tested with a controlled subprocess stub; missing signer,
  failure, timeout, missing output and malicious signer output are covered.
- Wheel ZIP integrity, every RECORD hash, and equality of packaged Python sources
  with project sources were checked.
- Final project ZIP is extracted, its Windows CMD setup script run, and its installed
  CLI used for version/doctor, fixture creation, inspect/extract/pack/reinspect,
  no-overwrite failure and a second run of all 22 tests before delivery.
- Project ZIP member CRCs and included wheel are checked after packaging.

**Not verified:** execution on macOS/Linux or Python versions other than 3.14.5;
real zsign signing, Apple certificate/profile validation or installation on an
iPhone. A Windows/macOS/Linux CI matrix is supplied but has not been run remotely.
No actual signing identity, provisioning profile or iOS device was supplied.

The fixture is unsigned and non-runnable. Signature presence and zsign exit status
are never presented as proof of installability. Locally generated certificates
cannot authorize ordinary iPhone installation without Apple-authorized signing.

See `TEST-RESULTS.txt` for captured local verification output. External
`SHA256SUMS.txt` lists hashes for delivered files; it is an integrity reference,
not a signed authenticity guarantee.
