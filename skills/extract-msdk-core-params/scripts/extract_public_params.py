#!/usr/bin/env python3
"""Read explicitly declared public integration metadata; Python 3.10+ stdlib only."""

import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
import zipfile
import zlib


MAX_APK_BYTES = 2 * 1024 * 1024 * 1024
MAX_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_TEXT_BYTES = 1024 * 1024
MAX_TOTAL_TEXT_BYTES = 16 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_OBSERVATIONS = 4096
MAX_WARNINGS = 128
MAX_DEPTH = 64
ANDROID = "{http://schemas.android.com/apk/res/android}"
FIELDS = (
    "package_id", "qq_app_id", "wechat_app_id", "msdk_game_id",
    "msdk_version", "channel_description", "https_hosts",
)
ALIASES = {
    "package_id": ("packageid", "packagename", "applicationid"),
    "qq_app_id": ("qqappid", "msdkqqappid"),
    "wechat_app_id": ("wechatappid", "wxappid", "msdkwxappid", "msdkwechatappid"),
    "msdk_game_id": ("msdkgameid",),
    "msdk_version": ("msdkversion", "msdksdkversion"),
    "channel_description": ("channeldescription", "channelname", "msdkchannelname", "msdkchanneldescription"),
    "https_hosts": ("publichttpshost", "publichttpshosts", "httpshost", "httpshosts", "msdkhttpshosts"),
}
FIELD_BY_ALIAS = {alias: field for field, aliases in ALIASES.items() for alias in aliases}
SENSITIVE_PARTS = (
    "secret", "token", "password", "passwd", "credential", "authorization",
    "privatekey", "signkey", "signature", "appkey", "accesskey", "session",
    "certificate", "keystore", "sdkkey", "cookie", "authcode", "clientsig",
)


class ExtractionError(Exception):
    """Contains a static code only, never input or parser exception text."""


class JObject(list):
    """Preserves duplicate JSON members for conflict reporting."""


def normalized(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def sensitive(name):
    norm = normalized(name)
    return any(part in norm for part in SENSITIVE_PARTS)


def safe_relative_path(name):
    if not name or len(name) > 1024 or "\\" in name or ":" in name:
        return False
    if name.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in name):
        return False
    return all(part not in ("", ".", "..") for part in name.split("/"))


def candidate(name):
    path = PurePosixPath(name)
    if any(sensitive(part) for part in path.parts):
        return False
    if path.parts[0].lower() in ("lib", "meta-inf", "original"):
        return False
    if name == "AndroidManifest.xml":
        return True
    if path.suffix.lower() in (".ini", ".properties", ".cfg", ".conf", ".json"):
        return True
    return path.suffix.lower() == ".xml" and (
        path.parts[0] == "assets"
        or (len(path.parts) >= 3 and path.parts[0] == "res" and path.parts[1].startswith("values"))
    )


def public_https_host(value):
    """Keep the DNS hostname only; never retain URL paths or credentials."""
    try:
        parts = urlsplit(value if "://" in value else "https://" + value)
        if parts.scheme.lower() != "https" or parts.username is not None or parts.password is not None:
            return None
        host = parts.hostname
        if not host or "*" in host or "\\" in value:
            return None
        # Accessing port also rejects invalid ports, without printing the URL.
        if parts.port is not None and not 1 <= parts.port <= 65535:
            return None
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        if host.endswith((".local", ".localhost", ".internal", ".lan", ".home", ".onion")):
            return None
        labels = host.split(".")
        if len(host) > 253 or len(labels) < 2 or labels[-1].isdigit():
            return None
        if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            return None
        return host
    except (ValueError, UnicodeError):
        return None


def valid_value(field, value):
    if field == "package_id":
        return value if len(value) <= 255 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", value) else None
    if field in ("qq_app_id", "msdk_game_id"):
        return value if re.fullmatch(r"[0-9]{1,20}", value) else None
    if field == "wechat_app_id":
        return value if re.fullmatch(r"wx[0-9a-fA-F]{16}", value) else None
    if field == "msdk_version":
        return value if re.fullmatch(r"v?[0-9]+(?:\.[0-9]+){0,4}(?:[-+][A-Za-z0-9._-]{1,32})?", value) and len(value) <= 64 else None
    if field == "channel_description":
        return value if 1 <= len(value) <= 80 and re.fullmatch(r"[\w .()/+-]+", value) and not sensitive(value) else None
    if field == "https_hosts":
        return public_https_host(value)
    return None


class Report:
    def __init__(self, kind, digest):
        self.digest = digest
        self.data = {
            "schema_version": 1,
            "input": {"kind": kind, "apk_sha256": digest},
            "fields": {field: {"status": "missing", "values": [], "unresolved": []} for field in FIELDS},
            "warnings": [],
        }
        self.observations = 0
        self.total_bytes = 0

    def warn(self, code, source=None):
        item = {"code": code}
        if source is not None:
            item["source"] = source
        if item not in self.data["warnings"]:
            if len(self.data["warnings"]) < MAX_WARNINGS:
                self.data["warnings"].append(item)
            elif self.data["warnings"][-1]["code"] != "warning_limit_reached":
                self.data["warnings"][-1] = {"code": "warning_limit_reached"}

    def reserve(self, size, source):
        if size > MAX_TEXT_BYTES:
            self.warn("text_file_size_exceeded", source)
            return False
        if self.total_bytes + size > MAX_TOTAL_TEXT_BYTES:
            self.warn("total_text_size_exceeded")
            return False
        self.total_bytes += size
        return True

    def add(self, field, value, source, location):
        if self.observations >= MAX_OBSERVATIONS:
            self.warn("observation_limit_reached")
            return
        self.observations += 1
        evidence = {"source": source, "location": location, "apk_sha256": self.digest}
        reason = "unsupported_value"
        clean = None
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            value = str(value).strip()
            if value.startswith(("@", "${", "?")):
                reason = "unresolved_reference"
            elif value and not any(ord(char) < 32 or ord(char) == 127 for char in value):
                clean = valid_value(field, value)
        result = self.data["fields"][field]
        if clean is None:
            result["unresolved"].append({"reason": reason, "evidence": evidence})
            return
        for item in result["values"]:
            if item["value"] == clean:
                if evidence not in item["evidence"]:
                    item["evidence"].append(evidence)
                return
        result["values"].append({"value": clean, "evidence": [evidence]})

    def known(self, key, value, source, location):
        if not isinstance(key, str) or sensitive(key):
            return
        field = FIELD_BY_ALIAS.get(normalized(key))
        if field:
            if field == "https_hosts" and isinstance(value, list) and not isinstance(value, JObject):
                for index, item in enumerate(value):
                    self.add(field, item, source, f"{location}/item:{index + 1}")
            else:
                self.add(field, value, source, location)

    def finish(self):
        for field, record in self.data["fields"].items():
            if len(record["values"]) > 1 and field != "https_hosts":
                record["status"] = "conflict"
            elif record["unresolved"]:
                record["status"] = "ambiguous"
            elif record["values"]:
                record["status"] = "found"
        return self.data


def parse_ini(text, source, report):
    blocked_section = False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";", "!")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            blocked_section = sensitive(stripped[1:-1])
            continue
        if blocked_section:
            continue
        match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)\s*[=:]\s*(.*?)\s*", line)
        if not match:
            continue
        key, value = match.groups()
        # Parse only the allowlist; unknown values and entire lines never leave this scope.
        if normalized(key) not in FIELD_BY_ALIAS or sensitive(key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            value = re.split(r"\s+[;#]", value, maxsplit=1)[0].strip()
        report.known(key, value, source, f"line:{number}")


def parse_json(text, source, report):
    try:
        root = json.loads(text, object_pairs_hook=JObject)
    except (ValueError, RecursionError):
        report.warn("malformed_json", source)
        return
    stack = [(root, "$", 0)]
    visited = 0
    while stack:
        obj, location, depth = stack.pop()
        visited += 1
        if visited > MAX_ENTRIES:
            report.warn("structure_limit_reached", source)
            return
        if depth > MAX_DEPTH:
            report.warn("structure_depth_exceeded", source)
            continue
        if isinstance(obj, JObject):
            for index, (key, value) in enumerate(obj, 1):
                if sensitive(key):
                    continue
                # Numeric positions do not disclose unknown or sensitive JSON keys.
                child = f"{location}/member:{index}"
                if normalized(key) in FIELD_BY_ALIAS:
                    report.known(key, value, source, child)
                elif isinstance(value, list):
                    stack.append((value, child, depth + 1))
        elif isinstance(obj, list):
            for index, value in enumerate(obj, 1):
                if isinstance(value, list):
                    stack.append((value, f"{location}/item:{index}", depth + 1))


def parse_xml(text, source, report):
    if re.search(r"<!\s*(DOCTYPE|ENTITY)\b", text, flags=re.IGNORECASE):
        report.warn("xml_dtd_or_entity_forbidden", source)
        return
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        report.warn("malformed_xml", source)
        return
    is_manifest = source == "AndroidManifest.xml"
    if is_manifest:
        if root.tag != "manifest":
            report.warn("unexpected_manifest_root", source)
            return
        if "package" in root.attrib:
            report.add("package_id", root.attrib["package"], source, "xml:/1/@package")
    stack = [(root, "xml:/1", False, 0)]
    index = 0
    while stack:
        element, location, blocked, depth = stack.pop()
        index += 1
        if index > MAX_ENTRIES:
            report.warn("structure_limit_reached", source)
            return
        if depth > MAX_DEPTH:
            report.warn("structure_depth_exceeded", source)
            continue
        tag = element.tag.rsplit("}", 1)[-1]
        key = element.get(ANDROID + "name", element.get("name", tag))
        blocked = blocked or sensitive(tag) or sensitive(key)
        if blocked:
            continue
        if is_manifest and tag == "meta-data":
            value = element.get(ANDROID + "value", element.get(ANDROID + "resource", ""))
            report.known(key, value, source, location)
        elif is_manifest and tag == "data" and element.get(ANDROID + "scheme", "").lower() == "https":
            if ANDROID + "host" in element.attrib:
                report.add("https_hosts", element.attrib[ANDROID + "host"], source, location + "/@host")
        elif not is_manifest and len(element) == 0:
            report.known(key, element.get("value", element.text or ""), source, location)
        stack.extend((child, f"{location}/{position}", blocked, depth + 1)
                     for position, child in reversed(list(enumerate(element, 1))))


def parse_content(raw, source, report):
    if source == "AndroidManifest.xml" and raw[:4] == b"\x03\x00\x08\x00":
        report.warn("binary_manifest_needs_decoding", source)
        return
    try:
        text = raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig")
    except UnicodeError:
        report.warn("binary_manifest_needs_decoding" if source == "AndroidManifest.xml" else "unsupported_text_encoding", source)
        return
    if "\x00" in text:
        report.warn("binary_manifest_needs_decoding" if source == "AndroidManifest.xml" else "binary_text_skipped", source)
        return
    suffix = PurePosixPath(source).suffix.lower()
    if suffix == ".json":
        parse_json(text, source, report)
    elif suffix == ".xml":
        parse_xml(text, source, report)
    else:
        parse_ini(text, source, report)


def apk_digest(path):
    if not path.is_file() or path.stat().st_size > MAX_APK_BYTES:
        raise ExtractionError("apk_missing_or_size_exceeded")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_APK_BYTES:
                raise ExtractionError("apk_size_exceeded")
            digest.update(chunk)
    return digest.hexdigest()


def guard_zip_directory(path):
    """Bound metadata allocation before ZipFile reads the central directory."""
    with path.open("rb") as stream:
        size = stream.seek(0, os.SEEK_END)
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    if position < 0 or len(tail) - position < 22:
        raise ExtractionError("invalid_apk_archive")
    _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, comment_size = struct.unpack_from("<4s4H2IH", tail, position)
    if len(tail) - position != 22 + comment_size or disk or cd_disk or disk_entries != entries:
        raise ExtractionError("unsupported_apk_archive")
    if entries == 65535 or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        raise ExtractionError("zip64_archive_unsupported")
    if entries > MAX_ENTRIES or cd_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise ExtractionError("archive_metadata_limit_exceeded")


def scan_apk(path, report):
    guard_zip_directory(path)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ExtractionError("archive_entry_limit_exceeded")
        counts = Counter(item.filename.casefold() for item in entries if not item.is_dir())
        for item in entries:
            if item.is_dir():
                continue
            source = item.filename
            if not safe_relative_path(item.orig_filename):
                report.warn("unsafe_archive_path")
                continue
            if not candidate(source):
                continue
            if counts[source.casefold()] > 1:
                report.warn("duplicate_archive_entry", source)
                continue
            if stat.S_ISLNK(item.external_attr >> 16):
                report.warn("archive_symlink_skipped", source)
                continue
            if item.flag_bits & 1:
                report.warn("encrypted_entry_skipped", source)
                continue
            if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                report.warn("unsupported_entry_compression", source)
                continue
            if item.file_size / max(1, item.compress_size) > MAX_COMPRESSION_RATIO:
                report.warn("compression_ratio_exceeded", source)
                continue
            if not report.reserve(item.file_size, source):
                continue
            try:
                with archive.open(item) as stream:
                    raw = stream.read(MAX_TEXT_BYTES + 1)
                if len(raw) > MAX_TEXT_BYTES:
                    report.warn("text_file_size_exceeded", source)
                    continue
                parse_content(raw, source, report)
            except (OSError, ValueError, RuntimeError, NotImplementedError, EOFError, zipfile.BadZipFile, zlib.error):
                report.warn("archive_entry_unreadable", source)


def reparse_point(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def scan_directory(root, report):
    stack = [root]
    visited = 0
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1
                    if visited > MAX_ENTRIES:
                        report.warn("directory_entry_limit_exceeded")
                        return
                    path = Path(entry.path)
                    source = path.relative_to(root).as_posix()
                    if not safe_relative_path(source):
                        report.warn("unsafe_directory_path")
                        continue
                    if any(sensitive(part) for part in PurePosixPath(source).parts):
                        continue
                    try:
                        if reparse_point(path) or not path.resolve().is_relative_to(root):
                            report.warn("directory_link_skipped", source)
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name.lower() not in ("lib", "meta-inf", "original") and not entry.name.startswith("smali"):
                                stack.append(path)
                        elif entry.is_file(follow_symlinks=False) and candidate(source):
                            if not report.reserve(path.stat().st_size, source):
                                continue
                            with path.open("rb") as stream:
                                raw = stream.read(MAX_TEXT_BYTES + 1)
                            if len(raw) > MAX_TEXT_BYTES:
                                report.warn("text_file_size_exceeded", source)
                            else:
                                parse_content(raw, source, report)
                    except (OSError, ValueError):
                        report.warn("directory_entry_unreadable", source)
        except OSError:
            report.warn("directory_unreadable")


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ExtractionError("invalid_arguments")


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("input", type=Path, help="An APK archive or an already decoded directory")
    parser.add_argument("--apk-source", type=Path, help="Original APK to hash for decoded-directory evidence; linkage remains unverified")
    parser.add_argument("--output", type=Path, help="Also create a new UTF-8 JSON report outside the input directory")
    try:
        args = parser.parse_args(argv)
        source = args.input.resolve()
        if not source.exists():
            raise ExtractionError("input_missing")
        is_directory = source.is_dir()
        if not is_directory and source.suffix.lower() != ".apk":
            raise ExtractionError("input_must_be_apk_or_directory")
        if args.apk_source and not is_directory:
            raise ExtractionError("apk_source_only_for_directory")
        output = args.output.resolve() if args.output else None
        if output is not None:
            if output == source or (is_directory and output.is_relative_to(source)) or (args.apk_source and output == args.apk_source.resolve()):
                raise ExtractionError("output_overlaps_input")
            if output.exists():
                raise ExtractionError("output_exists")
        digest_path = args.apk_source.resolve() if args.apk_source else (None if is_directory else source)
        digest = apk_digest(digest_path) if digest_path else None
        report = Report("decoded_directory" if is_directory else "apk", digest)
        if is_directory:
            report.warn("decoded_to_apk_link_unverified" if digest else "apk_digest_unavailable")
            scan_directory(source, report)
        else:
            scan_apk(source, report)
        rendered = json.dumps(report.finish(), ensure_ascii=False, indent=2) + "\n"
        if output is not None:
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        sys.stdout.write(rendered)
        return 0
    except ExtractionError as exc:
        code = str(exc)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, RecursionError):
        code = "input_or_output_unavailable"
    sys.stdout.write(json.dumps({"schema_version": 1, "error": {"code": code}}) + "\n")
    return 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
