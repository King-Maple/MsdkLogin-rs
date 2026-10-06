"""Synthetic APKs only; no game credentials or network access."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SCRIPT = SCRIPTS / "extract_core_params.py"


def signed_zip(pairs=(), ini=""):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("assets/MSDKConfig.ini", ini)
    data = output.getvalue()
    eocd = data.rfind(b"PK\x05\x06")
    cd = struct.unpack_from("<I", data, eocd + 16)[0]
    entries = b"".join(struct.pack("<QI", len(value) + 4, key) + value for key, value in pairs)
    block = struct.pack("<Q", len(entries) + 24) + entries
    block += struct.pack("<Q", len(entries) + 24) + b"APK Sig Block 42"
    patched = bytearray(data[:cd] + block + data[cd:])
    struct.pack_into("<I", patched, eocd + len(block) + 16, cd + len(block))
    return bytes(patched)


def channel_payload(text):
    data = text.encode("ascii")
    return struct.pack("<HH", 0x96FA, len(data)) + data


def version_dex(class_name, field_name, value):
    """Minimal DEX metadata fixture with one static string field."""
    strings = [class_name, "Ljava/lang/String;", field_name, value]
    data = bytearray(192)
    string_offsets = []
    for text in strings:
        raw = text.encode("ascii")
        string_offsets.append(len(data))
        data.extend(bytes([len(raw)]) + raw + b"\0")
    class_data = len(data)
    data.extend(b"\x01\x00\x00\x00\x00\x19")
    static_values = len(data)
    data.extend(b"\x01\x17\x03")
    data[:8] = b"dex\n035\0"
    struct.pack_into("<III", data, 32, len(data), 112, 0x12345678)
    struct.pack_into("<II", data, 56, 4, 112)
    struct.pack_into("<II", data, 64, 2, 128)
    struct.pack_into("<II", data, 80, 1, 136)
    struct.pack_into("<II", data, 96, 1, 144)
    struct.pack_into("<4I", data, 112, *string_offsets)
    struct.pack_into("<2I", data, 128, 0, 1)
    struct.pack_into("<HHI", data, 136, 0, 1, 2)
    struct.pack_into("<8I", data, 144, 0, 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, class_data, static_values)
    return bytes(data)


def aliased_strings_dex(overlapping=False):
    count = 640
    string_table, type_table, class_table = 112, 112 + count * 4, 112 + count * 8
    string_offset = class_table + count * 32
    data = bytearray(string_offset)
    name = b"L" + b"x" * 60000 + b";"
    length, encoded_length = len(name), bytearray()
    while length > 127:
        encoded_length.append((length & 127) | 128)
        length >>= 7
    encoded_length.append(length)
    # Overlapping offsets must hit the cumulative budget even though none
    # of them is identical to another offset. No bytecode is executed.
    if overlapping:
        data.extend(b"\x01" * count)
    data.extend(encoded_length + name + b"\0")
    data[:8] = b"dex\n035\0"
    struct.pack_into("<III", data, 32, len(data), 112, 0x12345678)
    for header, offset in [(56, string_table), (64, type_table), (96, class_table)]:
        struct.pack_into("<II", data, header, count, offset)
    for index in range(count):
        struct.pack_into("<I", data, string_table + index * 4, string_offset + (index if overlapping else 0))
        struct.pack_into("<I", data, type_table + index * 4, index)
        struct.pack_into("<I", data, class_table + index * 32, index)
    return data


class CoreExtractionTests(unittest.TestCase):
    def run_apk(self, data):
        with tempfile.TemporaryDirectory() as temp:
            apk = Path(temp) / "synthetic.apk"
            apk.write_bytes(data)
            process = subprocess.run(
                [sys.executable, "-B", str(SCRIPT), str(apk)],
                capture_output=True, text=True, encoding="utf-8", timeout=15,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            return json.loads(process.stdout), process.stdout

    def test_core_ini_and_signing_channel_are_reported_without_secret(self):
        payload = channel_payload("channelId=87654321\r\nother=PRIVATE_SENTINEL\r\n")
        apk = signed_zip([(0x71717874, payload)],
            "MSDK_URL=https://region.example.test\nMSDK_GAME_ID=777\n"
            "MSDK_SDK_KEY=PRIVATE_SENTINEL\nQQ_APP_ID=123456\n"
            "WECHAT_APP_ID=wx0123456789abcdef\nCHANNEL_ID=2\n")
        report, rendered = self.run_apk(apk)
        self.assertEqual(report["apk_sha256"], hashlib.sha256(apk).hexdigest())
        for key, expected in {"msdk_url": "https://region.example.test", "game_id": "777",
                              "channel_dis": "87654321", "qq_app_id": "123456"}.items():
            self.assertEqual(report["fields"][key]["status"], "found")
            self.assertEqual(report["fields"][key]["values"][0]["value"], expected)
        self.assertEqual(report["fields"]["sdk_key"]["status"], "found")
        self.assertNotIn("PRIVATE_SENTINEL", rendered)

    def test_conflicting_channel_sources_are_not_silently_selected(self):
        report, _ = self.run_apk(signed_zip(
            [(0x71717874, channel_payload("channelId=87654321\n"))],
            "MSDK_CHANNEL_DIS=12345678\n"))
        self.assertEqual(report["fields"]["channel_dis"]["status"], "conflict")
        self.assertFalse(report["core_complete"])

    def test_truncated_channel_payload_is_not_accepted(self):
        payload = channel_payload("channelId=87654321\n")[:-1]
        report, _ = self.run_apk(signed_zip([(0x71717874, payload)]))
        self.assertEqual(report["fields"]["channel_dis"]["status"], "ambiguous")
        self.assertIn("unsupported_channel_payload", report["warnings"])

    def test_duplicate_signing_channel_entries_are_ambiguous(self):
        payload = channel_payload("channelId=87654321\n")
        report, _ = self.run_apk(signed_zip([(0x71717874, payload)] * 2))
        self.assertEqual(report["fields"]["channel_dis"]["status"], "ambiguous")
        self.assertFalse(report["core_complete"])

    def test_versions_use_exact_sdk_classes_and_fields(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("classes.dex", version_dex(
                "Lcom/tencent/connect/common/Constants;", "SDK_VERSION", "3.5.99"))
            archive.writestr("classes2.dex", version_dex(
                "Lcom/itop/gcloud/msdk/pixui/core/BuildConfig;", "VERSION_NAME", "5.99.1.123"))
            archive.writestr("classes3.dex", version_dex(
                "Lcom/itop/gcloud/msdk/pixui/system/BuildConfig;", "VERSION_NAME", "5.1.2.3"))
        report, _ = self.run_apk(output.getvalue())
        self.assertEqual(report["fields"]["qq_sdk_version"]["values"][0]["value"], "3.5.99")
        self.assertEqual(report["fields"]["msdk_version"]["values"][0]["value"], "5.99.1.123")
        self.assertEqual(report["fields"]["msdk_version"]["status"], "found")

    def test_http_url_and_generic_channel_id_do_not_complete_core_fields(self):
        report, _ = self.run_apk(signed_zip(ini="MSDK_URL=http://example.test\nCHANNEL_ID=2\n"))
        self.assertEqual(report["fields"]["msdk_url"]["status"], "ambiguous")
        self.assertEqual(report["fields"]["channel_dis"]["status"], "missing")
        self.assertFalse(report["core_complete"])

    def test_skipped_config_makes_other_declarations_ambiguous(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("assets/MSDKConfig.ini", "MSDK_CHANNEL_DIS=1001\n")
            archive.writestr("assets/override.properties", "MSDK_CHANNEL_DIS=2002\n" + "#" * (1024 * 1024))
        report, _ = self.run_apk(output.getvalue())
        self.assertEqual(report["fields"]["channel_dis"]["status"], "ambiguous")
        self.assertFalse(report["core_complete"])

    def test_aliased_dex_strings_cannot_multiply_memory_usage(self):
        spec = importlib.util.spec_from_file_location("dex_versions_test", SCRIPTS / "dex_sdk_versions.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        data = aliased_strings_dex()
        tracemalloc.start()
        try:
            self.assertEqual(module.sdk_versions(data), [])
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 8 * 1024 * 1024)

    def test_overlapping_dex_strings_report_incomplete_versions(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("classes.dex", version_dex(
                "Lcom/tencent/connect/common/Constants;", "SDK_VERSION", "3.5.99"))
            archive.writestr("classes2.dex", aliased_strings_dex(overlapping=True))
        report, _ = self.run_apk(output.getvalue())
        self.assertEqual(report["fields"]["qq_sdk_version"]["status"], "ambiguous")
        self.assertIn("dex_unreadable", report["warnings"])


if __name__ == "__main__":
    unittest.main()
