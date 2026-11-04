from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
from pathlib import Path
import platform
import sys
import zlib

from . import __version__
from .archive import Limits, extract_ipa, inspect_ipa, pack_ipa
from .errors import Any2IPAError
from .signing import find_zsign, sign_ipa


def _limits(parser):
    defaults = Limits()
    parser.add_argument("--max-entries", type=int, default=defaults.max_entries)
    parser.add_argument("--max-file-bytes", type=int, default=defaults.max_file_bytes)
    parser.add_argument("--max-total-bytes", type=int, default=defaults.max_total_bytes)
    parser.add_argument("--max-archive-bytes", type=int, default=defaults.max_archive_bytes)
    parser.add_argument("--max-ratio", type=float, default=defaults.max_ratio)


def parser():
    root = argparse.ArgumentParser(
        prog="any2ipa", description="Inspect, extract, repack and re-sign existing iOS app packages.",
        epilog="Cannot convert APK/EXE/ZIP data into iOS code or create Apple-authorized signing assets.")
    root.add_argument("--version", action="version", version=f"Any2IPA {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in (("inspect", "Validate the complete archive and show app metadata"),
                            ("extract", "Extract into a NEW directory"),
                            ("pack", "Pack an extracted IPA root or .app directory"),
                            ("sign", "Re-sign an existing IPA using external zsign")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("source", type=Path)
        command.add_argument("--json", action="store_true", help="Print a machine-readable result")
        _limits(command)
        if name != "inspect":
            command.add_argument("-o", "--output", type=Path, required=True,
                                 help="New output path; its parent must already exist")
        if name == "pack":
            command.add_argument("--compression", type=int, choices=range(10), default=6)
        if name == "sign":
            command.add_argument("--key", type=Path, required=True, help="Apple certificate + private key (.p12/.pfx)")
            command.add_argument("--profile", type=Path, action="append", required=True,
                                 help="Apple .mobileprovision; repeat for extensions (requires recent zsign)")
            command.add_argument("--zsign", help="Path to a trusted zsign executable")
            command.add_argument("--timeout", type=int, default=300)
            secret = command.add_mutually_exclusive_group()
            secret.add_argument("--password-env", metavar="NAME", help="Read P12 password from environment variable NAME")
            secret.add_argument("--empty-password", action="store_true", help="Use an empty P12 password")
    doctor = commands.add_parser("doctor", help="Check local prerequisites without executing zsign")
    doctor.add_argument("--zsign")
    doctor.add_argument("--json", action="store_true")
    return root


def _print(result, as_json):
    if as_json:
        print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    else:
        # JSON-escape values even in text output: metadata may contain terminal
        # escape sequences or deceptive embedded newlines.
        for key, value in result.items():
            print(f"{key}: {json.dumps(value, ensure_ascii=True)}")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            result = {"any2ipa": __version__, "python": platform.python_version(),
                      "platform": platform.system(), "zlib": zlib.ZLIB_VERSION,
                      "zsign": find_zsign(args.zsign), "core_ready": True,
                      "apple_signing_assets_generated": False,
                      "note": "zsign is optional for archive operations; no signing/installation verification performed."}
        else:
            limits = Limits(**{f.name: getattr(args, f.name) for f in dataclasses.fields(Limits)})
            if args.command == "inspect":
                result = inspect_ipa(args.source, limits)
            elif args.command == "extract":
                result = extract_ipa(args.source, args.output, limits)
            elif args.command == "pack":
                result = pack_ipa(args.source, args.output, limits, args.compression)
            else:
                if args.empty_password:
                    password = ""
                elif args.password_env:
                    if args.password_env not in os.environ:
                        raise Any2IPAError("The requested password environment variable is not set.")
                    password = os.environ[args.password_env]
                elif sys.stdin.isatty():
                    password = getpass.getpass("P12 password (hidden): ")
                else:
                    raise Any2IPAError("Use --password-env NAME or --empty-password in noninteractive mode.")
                result = sign_ipa(args.source, args.output, key=args.key,
                                  profiles=args.profile, password=password, zsign=args.zsign,
                                  timeout=args.timeout, limits=limits)
        _print(result, args.json)
        return 0
    except (Any2IPAError, OSError, ValueError, zlib.error, RecursionError) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        else:
            print("any2ipa: " + json.dumps(str(exc), ensure_ascii=True), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("any2ipa: cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
