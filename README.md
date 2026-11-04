# Any2IPA

**A modern, open-source toolkit for signing and packaging iOS applications.**

Any2IPA simplifies the process of signing IPA files with your own Apple developer certificates. It combines a clean desktop interface, command-line functionality, and a reliable signing workflow in one lightweight tool.

Built with C++20 and Qt6, with zsign integration for iOS code signing.

**Simple to use. Powerful when you need it.**

## Overview

Working with IPA files shouldn't require a complicated setup or an unnecessarily complex workflow.

Any2IPA brings the essential tools together. Select an IPA, provide your signing credentials, and let the application handle validation, signing, and repackaging.

Whether you're preparing a development build, testing an application, or re-signing software you're authorized to modify, Any2IPA is designed to make the process more efficient.

## Features

**Application Signing**

Sign existing IPA files using P12/PFX certificates and compatible Apple provisioning profiles. Any2IPA handles the signing process and generates a new IPA package.

**Modern Desktop Interface**

A straightforward Qt6 interface with drag-and-drop file selection, application information, signing progress, and detailed logs.

**Command-Line Support**

Perform signing and IPA management operations directly from the terminal. Suitable for repeatable development workflows and local automation.

**Application Inspection**

Read application metadata, including the Bundle ID, display name, version, and package structure.

**Automatic Repackaging**

Extract, process, sign, and repackage iOS application bundles while preserving the required IPA directory structure.

**Local Processing**

Application files, certificates, and provisioning profiles are processed locally. No mandatory account, external server, or cloud upload is required.

## Getting Started

### Requirements

- C++20-compatible compiler
- Qt6
- CMake 3.21 or newer
- zsign
- Valid Apple signing certificate (`.p12` or `.pfx`)
- Compatible provisioning profile (`.mobileprovision`)

### Building from Source

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Any2IPA.git
cd Any2IPA
```

Configure and compile:

```bash
cmake -S . -B build
cmake --build build --config Release
```

The build environment must have Qt6 and the required signing dependencies configured.

## Usage

### Desktop Application

Open Any2IPA and select the IPA file you want to sign.

Import your signing certificate, enter its password, and choose the appropriate provisioning profile.

Review the application information and select an output location.

Click **Sign IPA** to begin processing.

Once the operation completes successfully, the signed IPA will be available at your selected destination.

### Command-Line Interface

Sign an application:

```bash
any2ipa sign --ipa MyApp.ipa --certificate Developer.p12 --profile Developer.mobileprovision --output Signed.ipa
```

Inspect application information:

```bash
any2ipa info MyApp.ipa
```

Validate an IPA package:

```bash
any2ipa verify MyApp.ipa
```

Extract an IPA archive:

```bash
any2ipa extract MyApp.ipa
```

Display available commands:

```bash
any2ipa --help
```

The CLI should request certificate passwords securely without exposing them in terminal history or process arguments.

## How Signing Works

Any2IPA uses a structured signing process to prepare an existing iOS application for distribution or installation.

1. **Inspection** — Reads the IPA archive and identifies the application bundle.
2. **Validation** — Checks the signing certificate, provisioning profile, application identifier, and relevant entitlements.
3. **Preparation** — Prepares the application bundle and embedded components for signing.
4. **Code Signing** — Uses the configured signing engine to apply the signature.
5. **Packaging** — Rebuilds the IPA archive with the signed application.
6. **Verification** — Checks the resulting package and reports the signing outcome.

The resulting IPA must still meet Apple's requirements for the intended installation or distribution method.

## Supported Files

Any2IPA works with existing iOS application packages and the credentials required to sign them.

- `.ipa` — iOS application packages.
- `.p12` / `.pfx` — PKCS#12 signing credentials.
- `.mobileprovision` — Apple provisioning profiles.

An IPA must contain a valid iOS application bundle. Android APK files, Windows EXE files, and arbitrary ZIP archives cannot be turned into functional iOS applications through signing alone.

## Security

Any2IPA is designed to keep signing operations under the user's control.

Certificate passwords should never be stored in plaintext or included in logs. Temporary files should be handled securely and removed when they are no longer required.

The application should validate input archives, protect against unsafe extraction paths, and avoid exposing signing credentials to unrelated processes.

Users are responsible for protecting their private keys and ensuring they have permission to sign or modify the applications they process.

## Troubleshooting

**Certificate cannot be loaded**

Check that the certificate is valid, its password is correct, and it contains the private key required for signing.

**Provisioning profile is incompatible**

Verify that the provisioning profile matches the signing certificate, Bundle ID, entitlements, and intended distribution method.

**Signing fails**

Check the signing logs, confirm that zsign is correctly configured, and verify the IPA's application structure.

**Signed IPA cannot be installed**

A successful signing operation does not guarantee installation. Check device eligibility, provisioning restrictions, application compatibility, and iOS requirements.

## Contributing

Any2IPA is an open-source project, and contributions are welcome.

If you encounter a bug, have an improvement in mind, or want to contribute code, open an issue or submit a pull request.

Please keep contributions focused, documented, and consistent with the project's architecture.

## License

See the `LICENSE` file for the terms under which Any2IPA is distributed.

## Acknowledgments

Any2IPA builds on ideas and technologies from the open-source iOS development ecosystem, including [zsign](https://github.com/zhlynn/zsign) and [CyberTKR/IpaSigner](https://github.com/CyberTKR/IpaSigner).

---

**Any2IPA** - iOS signing, without the complexity.
