#!/usr/bin/env python3
"""Extract redacted MSDK builder parameters, signing channel and DEX SDK versions."""

from collections import Counter
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
from urllib.parse import urlsplit
import zipfile

from dex_sdk_versions import sdk_versions
from extract_public_params import (
    ExtractionError, SafeParser, apk_digest, guard_zip_directory, safe_relative_path,
)

FIELDS = ("msdk_url", "game_id", "sdk_key", "channel_dis", "package_name",
          "qq_app_id", "signature_md5", "wechat_app_id", "msdk_version", "qq_sdk_version")
ALIASES = {
    "MSDK_URL": "msdk_url", "MSDK_GAME_ID": "game_id", "MSDK_SDK_KEY": "sdk_key",
    "MSDK_CHANNEL_DIS": "channel_dis", "QQ_APP_ID": "qq_app_id",
    "MSDK_QQ_APP_ID": "qq_app_id", "WECHAT_APP_ID": "wechat_app_id",
    "WX_APP_ID": "wechat_app_id", "MSDK_WECHAT_APP_ID": "wechat_app_id",
    "MSDK_WX_APP_ID": "wechat_app_id", "MSDK_VERSION": "msdk_version",
    "MSDK_SDK_VERSION": "msdk_version", "QQ_SDK_VERSION": "qq_sdk_version",
}
MAX_SIGNING_BLOCK = 4 * 1024 * 1024
MAX_DEX = 32 * 1024 * 1024


def valid(field, value):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        return False
    if value.startswith(("@", "${")):
        return False
    if field == "msdk_url":
        try:
            url = urlsplit(value)
            _ = url.port
            return (url.scheme == "https" and bool(url.hostname) and url.username is None
                    and url.password is None and url.path in ("", "/")
                    and not any(c in value for c in ("?", "#", "\\"))
                    and not any(c.isspace() for c in value))
        except ValueError:
            return False
    if field in ("game_id", "qq_app_id"):
        return bool(re.fullmatch(r"[0-9]{1,20}", value))
    if field == "wechat_app_id":
        return bool(re.fullmatch(r"wx[0-9a-fA-F]{16}", value))
    if field == "package_name":
        return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", value))
    if field == "signature_md5":
        return bool(re.fullmatch(r"[0-9a-f]{32}", value))
    if field in ("msdk_version", "qq_sdk_version"):
        return bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,4}(?:[._-][A-Za-z0-9]+)?", value))
    if field == "channel_dis":
        return bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", value))
    return True


class Report:
    def __init__(self, digest):
        self.digest = digest
        self.values = {field: {} for field in FIELDS}
        self.unresolved = {field: [] for field in FIELDS}
        self.warnings = []
        self.signature = {"verified": False}
        self.observations = 0

    def warn(self, code):
        if code not in self.warnings:
            self.warnings.append(code)

    def uncertain(self, fields, source, location):
        evidence = {"source": source, "location": location}
        for field in fields:
            # Missing coverage must affect status, but thousands of skipped
            # inputs must not multiply the evidence report without a bound.
            if len(self.unresolved[field]) < 32 and evidence not in self.unresolved[field]:
                self.unresolved[field].append(evidence)

    def add(self, field, value, source, location):
        self.observations += 1
        if self.observations > 4096:
            self.uncertain((field,), "input", "observation limit")
            self.warn("observation_limit_exceeded")
            return
        evidence = {"source": source, "location": location}
        if not valid(field, value):
            self.uncertain((field,), source, location)
        elif len(self.values[field]) < 64:
            self.values[field].setdefault(value, []).append(evidence)
        else:
            self.uncertain((field,), source, location)
            self.warn("field_value_limit_exceeded")

    def finish(self):
        fields = {}
        for field, values in self.values.items():
            status = ("conflict" if len(values) > 1 else "ambiguous" if self.unresolved[field]
                      else "found" if values else "missing")
            fields[field] = {
                "status": status,
                "values": [{"value": "[REDACTED]" if field == "sdk_key" else value,
                            "evidence": evidence} for value, evidence in values.items()],
                "unresolved": self.unresolved[field],
            }
        # Completeness covers both channels; a one-channel application may omit
        # the other channel deliberately, as described in the skill.
        return {"schema_version": 1, "apk_sha256": self.digest, "fields": fields,
                "core_complete": all(fields[key]["status"] == "found" for key in FIELDS[:8]),
                "signature_verification": self.signature, "warnings": self.warnings}


def read_channel(apk, cd_offset, report):
    def incomplete(code):
        report.warn(code)
        report.uncertain(("channel_dis",), "APK Signing Block", code)

    with apk.open("rb") as stream:
        if cd_offset < 24:
            return
        stream.seek(cd_offset - 24)
        tail = stream.read(24)
        if tail[8:] != b"APK Sig Block 42":
            report.warn("signing_channel_not_present")
            return
        size, = struct.unpack_from("<Q", tail)
        if size < 24 or size > MAX_SIGNING_BLOCK or size + 8 > cd_offset:
            incomplete("invalid_signing_block_size")
            return
        start = cd_offset - size - 8
        stream.seek(start)
        block = stream.read(size + 8)
    if len(block) != size + 8 or struct.unpack_from("<Q", block)[0] != size:
        incomplete("invalid_signing_block_size")
        return
    position, payloads = 8, []
    while position < len(block) - 24:
        if position + 12 > len(block) - 24:
            incomplete("invalid_signing_entry")
            return
        length, block_id = struct.unpack_from("<QI", block, position)
        if length < 4 or position + 8 + length > len(block) - 24:
            incomplete("invalid_signing_entry")
            return
        if block_id == 0x71717874:
            payloads.append((block[position + 12:position + 8 + length], start + position))
        position += 8 + length
    if len(payloads) > 1:
        report.uncertain(("channel_dis",), "APK Signing Block", "duplicate 0x71717874 entries")
        return
    if not payloads:
        report.warn("signing_channel_not_present")
        return
    payload, offset = payloads[0]
    if len(payload) < 4:
        incomplete("unsupported_channel_payload")
        return
    magic, size = struct.unpack_from("<HH", payload)
    if magic != 0x96FA or size != len(payload) - 4:
        incomplete("unsupported_channel_payload")
        return
    try:
        text = payload[4:].decode("utf-8")
    except UnicodeError:
        incomplete("unsupported_channel_payload")
        return
    for line in text.splitlines():
        match = re.fullmatch(r"\s*channelId\s*=\s*(.*?)\s*", line)
        if match:
            report.add("channel_dis", match[1], "APK Signing Block",
                       f"0x71717874@0x{offset:x}/channelId")


def scan_entries(archive, report):
    counts = Counter(info.filename.casefold() for info in archive.infolist())
    total = 0
    for info in archive.infolist():
        name = info.filename
        dex = bool(re.fullmatch(r"classes\d*\.dex", name))
        config = name.startswith("assets/") and Path(name).suffix.lower() in (".ini", ".properties", ".cfg", ".conf")
        if not (dex or config):
            continue
        affected = ("msdk_version", "qq_sdk_version") if dex else set(ALIASES.values())

        def skipped(code):
            report.warn(code)
            report.uncertain(affected, name, code)

        if not safe_relative_path(name) or counts[name.casefold()] != 1 or info.flag_bits & 1:
            skipped("unsafe_or_duplicate_entry_skipped")
            continue
        limit = MAX_DEX if dex else 1024 * 1024
        if (info.file_size > limit or total + info.file_size > 128 * 1024 * 1024
                or info.file_size / max(1, info.compress_size) > 200):
            skipped("entry_read_limit_exceeded")
            continue
        total += info.file_size
        try:
            with archive.open(info) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                skipped("entry_read_limit_exceeded")
                continue
            if dex:
                for field, value, location in sdk_versions(data):
                    report.add(field, value, name, location)
            else:
                # Keys and assignment syntax are ASCII. Unrelated browser
                # metadata/comments may use a legacy encoding; only selected
                # values must decode as UTF-8. NULs indicate a binary or wide
                # encoding that this scanner cannot safely classify.
                if b"\0" in data:
                    raise ValueError("unsupported_config_encoding")
                for number, line in enumerate(data.removeprefix(b"\xef\xbb\xbf").splitlines(), 1):
                    match = re.match(rb"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
                    field = ALIASES.get(match[1].decode("ascii").upper()) if match else None
                    if field:
                        try:
                            value = match[2].decode("utf-8")
                        except UnicodeError:
                            report.warn("config_value_not_utf8")
                            report.uncertain((field,), name, f"line:{number}")
                        else:
                            report.add(field, value, name, f"line:{number}")
        except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile, struct.error):
            skipped("dex_unreadable" if dex else "config_unreadable")


def verify_apk(apk, report, jar, java):
    if jar is None:
        report.warn("apksig_jar_required_for_manifest_and_certificate")
        return
    if not jar.is_file():
        report.warn("apksig_jar_missing")
        return
    executable = java or shutil.which("java")
    if not executable:
        report.warn("java_required")
        return
    try:
        result = subprocess.run(
            [str(executable), "--class-path", str(jar), str(Path(__file__).with_name("VerifyApk.java")), str(apk)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        )
        parsed = json.loads(result.stdout)
        if result.returncode or parsed.get("verified") is not True:
            report.warn("apk_signature_verification_failed")
            return
        report.signature = {key: parsed[key] for key in ("verified", "v1", "v2", "v3", "warning_count")}
        report.add("package_name", parsed["package_name"], "AndroidManifest.xml", "manifest/@package")
        certificates = parsed["certificates"]
        for index, cert in enumerate(certificates):
            report.add("signature_md5", cert["md5"], "APK verified signer certificate", f"signer:{index + 1}")
        if len(certificates) > 1:
            report.uncertain(("signature_md5",), "APK verified signer certificate", "multiple signers; SDK selection must be checked")
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
        report.warn("apk_verifier_unavailable_or_failed")


def main():
    parser = SafeParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--apksig-jar", type=Path, help="Android apksig or apksigner JAR; enables verified certificate and binary Manifest extraction")
    parser.add_argument("--java", help="JDK 17+ java executable; otherwise use java from PATH")
    parser.add_argument("--output", type=Path, help="Create a new redacted JSON report")
    try:
        args = parser.parse_args()
        apk = args.apk.resolve()
        if apk.suffix.lower() != ".apk":
            raise ExtractionError("input_must_be_apk")
        if args.output and (args.output.resolve() == apk or args.output.exists()):
            raise ExtractionError("output_exists_or_overlaps_input")
        digest = apk_digest(apk)
        guard_zip_directory(apk)
        report = Report(digest)
        with zipfile.ZipFile(apk) as archive:
            scan_entries(archive, report)
            read_channel(apk, archive.start_dir, report)
        verify_apk(apk, report, args.apksig_jar, args.java)
        rendered = json.dumps(report.finish(), ensure_ascii=False, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        sys.stdout.write(rendered)
        return 0
    except ExtractionError as error:
        code = str(error)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, struct.error):
        code = "input_or_output_unavailable"
    print(json.dumps({"error": {"code": code}}))
    return 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
