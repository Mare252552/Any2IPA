"""Create an UNSIGNED, NON-RUNNABLE archive fixture for learning the CLI."""
import argparse
from pathlib import Path
import plistlib
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
args = parser.parse_args()
with zipfile.ZipFile(args.output, "x", compression=zipfile.ZIP_STORED) as archive:
    archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({
        "CFBundleIdentifier": "org.example.any2ipa.demo", "CFBundleExecutable": "Demo",
        "CFBundleName": "Any2IPA Demo", "CFBundleVersion": "1"}))
    archive.writestr("Payload/Demo.app/Demo", b"NOT EXECUTABLE: archive fixture only\n")
print("Created an unsigned, non-runnable test fixture:", args.output)
