"""Invoke a user-supplied zsign binary; never download or invent credentials."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .archive import (Limits, _parent_target, extract_ipa, inspect_ipa, pack_ipa,
                      publish_file, regular_file)
from .errors import Any2IPAError


def find_zsign(explicit: str | None = None) -> str | None:
    candidate = explicit or os.environ.get("ANY2IPA_ZSIGN") or "zsign"
    found = shutil.which(candidate)
    if found is None:
        return None
    path = Path(found).resolve(strict=True)
    # Windows batch scripts are implicitly interpreted by a shell even with
    # shell=False. Accept a native executable only on Windows.
    if os.name == "nt" and path.suffix.lower() != ".exe":
        raise Any2IPAError("On Windows --zsign must point to a native zsign.exe.")
    return str(regular_file(path))


def sign_ipa(source: Path, output: Path, *, key: Path, profiles: list[Path],
             password: str = "", zsign: str | None = None, timeout: int = 300,
             limits: Limits = Limits()) -> dict:
    if timeout <= 0:
        raise Any2IPAError("Signing timeout must be positive.")
    if not profiles:
        raise Any2IPAError("At least one Apple provisioning profile is required.")
    key_path = regular_file(key).resolve()
    if key_path.suffix.lower() not in (".p12", ".pfx"):
        raise Any2IPAError("Use a PKCS#12 .p12 or .pfx containing your certificate and private key.")
    profile_paths = [regular_file(p).resolve() for p in profiles]
    executable = find_zsign(zsign)
    if not executable:
        raise Any2IPAError("zsign was not found. Install it and use --zsign or ANY2IPA_ZSIGN.")
    target = _parent_target(output)
    with tempfile.TemporaryDirectory(prefix=".any2ipa-sign-", dir=target.parent) as temporary:
        work = Path(temporary)
        # zsign only receives a freshly generated ZIP after defensive extraction.
        extract_ipa(source, work / "tree", limits)
        normalized = work / "input.ipa"
        pack_ipa(work / "tree", normalized, limits)
        signed = work / "signed.ipa"
        command = [executable, "-f", "-k", str(key_path), "-p", password]
        for profile in profile_paths:
            command.extend(["-m", str(profile)])
        command.extend(["-o", str(signed), "-z", "6", str(normalized)])
        # zsign exposes -p only: the secret can be visible in the local process
        # list. Do not echo commands, child output or include secrets in errors.
        environment = os.environ.copy()
        for name in ("ANY2IPA_P12_PASSWORD",):
            environment.pop(name, None)
        try:
            completed = subprocess.run(command, shell=False, cwd=work,
                                       env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise Any2IPAError(f"zsign timed out after {timeout} seconds; no output was published.") from None
        except OSError:
            raise Any2IPAError("Could not execute zsign; check binary compatibility and permissions.") from None
        if completed.returncode:
            raise Any2IPAError(f"zsign failed (exit {completed.returncode}); check credentials, profiles and input. No output published.")
        if not signed.is_file():
            raise Any2IPAError("zsign reported success without producing an IPA.")
        result = inspect_ipa(signed, limits)
        if not result["signature_resources_present"] or not result["embedded_profile_present"]:
            raise Any2IPAError("zsign output is missing signature resources or embedded profile.")
        # Sanitize the signer's ZIP too. This preserves file bytes, including
        # signatures, while dropping archive-level attributes and path ambiguity.
        extract_ipa(signed, work / "signed-tree", limits)
        clean = work / "final.ipa"
        pack_ipa(work / "signed-tree", clean, limits)
        publish_file(clean, target)
    result["output"] = str(target)
    result["signer_exit_code"] = 0
    result["warning"] = ("zsign completed; Apple trust, entitlements, device eligibility, "
                         "certificate validity and installation have NOT been verified.")
    return result
