# Any2IPA

**Automatic IPA packaging and signing. One command. Zero manual configuration.**

Any2IPA is an open-source command-line utility that automates the process of preparing, signing, and packaging iOS applications.

No graphical interface, manual certificate imports, or complicated signing configuration.

Provide an IPA file and let Any2IPA handle the rest.

## What is Any2IPA?

Any2IPA is designed for developers who want a straightforward way to process IPA packages without manually configuring signing tools.

The utility automatically prepares its signing environment, generates local signing materials when necessary, processes the application bundle, and exports the resulting IPA.

Everything is controlled from the terminal.

## Features

- **One-Command Signing** — Process IPA files using a single terminal command.
- **Automatic Setup** — Configure the required signing utilities automatically.
- **Local Certificate Generation** — Generate self-signed certificates without requiring users to provide P12 or PFX files.
- **Automatic IPA Extraction** — Extract and inspect application packages.
- **Bundle Inspection** — Detect application identifiers, versions, and metadata.
- **Signing Engine Integration** — Automatically configure and invoke the signing backend.
- **Automatic Repackaging** — Rebuild IPA archives after processing.
- **Output Verification** — Validate package structure and report signing results.
- **Offline Processing** — Process files locally after dependencies have been installed.
- **CLI Interface** — No graphical interface or browser required.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Any2IPA.git
cd Any2IPA
```

Install Any2IPA:

```bash
python -m pip install .
```

The installer configures the Python package. Any additional platform-specific signing dependencies are handled by the setup process.

## Usage

Signing an IPA is designed to be as simple as:

```bash
any2ipa sign application.ipa
```

Any2IPA performs the following operations automatically:

1. Validates the input archive.
2. Extracts the iOS application bundle.
3. Inspects application metadata.
4. Prepares the signing environment.
5. Generates local signing materials if necessary.
6. Applies the selected signing method.
7. Repackages the application.
8. Checks the output archive.
9. Saves the resulting IPA.

Output:

```text
application_signed.ipa
```

### Custom Output

```bash
any2ipa sign application.ipa --output final.ipa
```

### Inspect an IPA

```bash
any2ipa info application.ipa
```

### Verify an IPA

```bash
any2ipa verify application.ipa
```

### Diagnose the Environment

```bash
any2ipa doctor
```

## Signing Methods

Any2IPA distinguishes between two types of signing.

### Local Self-Signing

Automatically generates a local certificate and applies a cryptographic signature without requiring an Apple developer account.

This method is useful for package processing and environments that explicitly accept such signatures.

A self-signed IPA is not automatically trusted by iOS and generally cannot be installed on an ordinary, unmodified iPhone.

### Apple-Authorized Signing

Uses a valid Apple-issued signing identity and compatible provisioning resources.

This method can produce installable IPA packages when all Apple requirements are satisfied.

Apple-authorized signing cannot be generated from nothing or replaced with a self-signed certificate.

## Design Principles

**Automation first.** Eliminate unnecessary manual configuration.

**Terminal native.** Every operation should be accessible through simple commands.

**Local by default.** Keep application packages and locally generated signing materials on the user's machine.

**Transparent results.** Clearly distinguish between a cryptographically signed IPA and an Apple-authorized, installable IPA.

**No false success.** Never report that an IPA is installable unless the relevant requirements have been verified.

## Contributing

Contributions, bug reports, and feature suggestions are welcome.

Any2IPA is intended to be a practical, transparent, and extensible open-source signing utility.

## License

See the `LICENSE` file for licensing information.

---

**Any2IPA. One command. Your IPA.**
