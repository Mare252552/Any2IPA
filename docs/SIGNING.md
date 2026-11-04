# Signing requirements and zsign setup

An IPA is a ZIP container. Packaging does not compile an iOS app and does not
authorize it to run. Ordinary iPhones require Apple-authorized signing for their
installation/distribution route. Creating a key, CSR or self-signed P12 locally
does **not** produce an Apple-issued certificate or Apple-authorized profile.

Supply all of the following yourself:

1. An already compiled iOS **device** app/IPA, with permission to use and sign it.
2. An appropriate Apple-issued signing certificate and its matching private key,
   exported together as `.p12`/`.pfx` (and its password).
3. A valid Apple provisioning profile matching the bundle ID, team, certificate,
   capabilities/entitlements and applicable target devices/distribution route.
4. Matching profiles for extensions when needed, plus a compatible trusted zsign.

Development and registered-device Ad Hoc distribution have device restrictions.
An App Store distribution profile does not make an IPA freely sideloadable.
Enterprise distribution has organization eligibility/use restrictions. Xcode's
Personal Team can provide Apple-managed signing for personal testing with limits;
it is still Apple-authorized provisioning and is not created by this tool.

An **ad-hoc code signature** (`zsign -a`) is different from Apple's **Ad Hoc
distribution** using a certificate and registered-device profile. The former
alone does not authorize installation on ordinary iPhones. Any2IPA intentionally
requires a P12/PFX and profile rather than exposing that misleading shortcut.

## Install zsign separately

Follow the authoritative [upstream README](https://github.com/zhlynn/zsign#build).
Review the source/release you choose; do not execute binaries from random mirrors.
These commands follow the upstream layout checked on 2026-11-04. Upstream can change.
Any2IPA does not automatically fetch or execute downloaded code.

macOS (requires Git, Xcode Command Line Tools, make and Homebrew):

```sh
brew install pkg-config openssl
git clone https://github.com/zhlynn/zsign.git
cd zsign/build/macos
make
./zsign -v
```

Ubuntu/Debian (upstream makefile also needs make):

```sh
sudo apt-get update
sudo apt-get install git g++ make pkg-config libssl-dev
git clone https://github.com/zhlynn/zsign.git
cd zsign/build/linux
make
./zsign -v
```

Windows: clone the same repository, install Visual Studio 2022 with C++ desktop
build tools, open `build/windows/vs2022/zsign.sln`, and build the native target.
Use the resulting executable with `--zsign C:\absolute\path\zsign.exe`.
Follow the selected revision's build configuration for any OpenSSL/library setup;
the Python setup script does not install the compiler or native libraries.

Pass the built executable's absolute path to `--zsign` or add its directory to
PATH. `any2ipa doctor` checks discovery only; it does not execute the file or
check signing compatibility. Manual `zsign -v` is useful for recording a version.
If your selected revision places the binary elsewhere, use that actual path.

## What success means

The CLI validates the original IPA, creates a normalized temporary IPA, invokes
zsign with `-f -k KEY -p PASSWORD -m PROFILE -o OUTPUT -z 6 INPUT`, checks its exit
status and archive result, then republishes a normalized IPA. Multiple profiles
produce repeated `-m` flags. It requires signature resources and an embedded
profile in the result, but their presence does not prove they are valid.

It does not validate Apple certificate chains, CMS profile signatures, expiry,
revocation, entitlement coverage, device UDIDs or code signatures. Check these
with appropriate Apple tooling and test on an eligible device. zsign can fail on
encrypted/App-Store-protected binaries, unsupported layouts or incompatible keys.
Re-signing does not remove DRM or convert simulator apps to device apps.

Phone deployment is separate: use an authorized route such as Xcode, Apple
Configurator, TestFlight, App Store or eligible managed distribution as applicable.
Developer Mode and other device requirements depend on the distribution route.

## Primary references

- [Apple: create a development provisioning profile](https://developer.apple.com/help/account/provisioning-profiles/create-a-development-provisioning-profile/)
- [Apple: distributing your app to registered devices](https://developer.apple.com/documentation/xcode/distributing-your-app-to-registered-devices)
- [Apple: distribution methods](https://help.apple.com/xcode/mac/current/en.lproj/dev31de635e5.html)
- [Apple: Personal Team and developer account](https://developer.apple.com/help/account/basics/about-your-developer-account)
- [zsign source and usage](https://github.com/zhlynn/zsign)
