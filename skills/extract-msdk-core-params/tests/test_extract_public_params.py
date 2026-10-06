"""Synthetic APK fixtures; this suite never reads a real game or sends requests."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract_public_params.py"
ANDROID = "http://schemas.android.com/apk/res/android"
PRIVATE_CONTAINER_NAMES = (
    "SDK_KEY", "SDK_SDK_KEY", "msdk.key", "Cookie", "HTTP_COOKIE",
    "AUTH_CODE", "oauth.auth-code", "CLIENT_SIGNATURE", "CLIENT_SIGN", "client.sig",
)


class ExtractPublicParamsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def apk(self, files, name="fixture.apk", compression=zipfile.ZIP_STORED):
        target = self.root / name
        with zipfile.ZipFile(target, "w", compression=compression) as archive:
            for source, content in files:
                archive.writestr(source, content)
        return target

    def decoded(self, files):
        target = self.root / "decoded"
        target.mkdir(exist_ok=True)
        for source, content in files:
            dest = target / source
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
        return target

    def run_script(self, target, *args, expected=0):
        process = subprocess.run(
            [sys.executable, str(SCRIPT), str(target), *map(str, args)],
            text=True, capture_output=True, encoding="utf-8", timeout=15,
        )
        self.assertEqual(process.returncode, expected, process.stderr)
        self.assertEqual(process.stderr, "")
        return json.loads(process.stdout), process.stdout

    def values(self, report, field):
        return [item["value"] for item in report["fields"][field]["values"]]

    def codes(self, report):
        return {item["code"] for item in report["warnings"]}

    def test_text_manifest_and_config_have_digest_and_locations(self):
        manifest = f'''<manifest xmlns:android="{ANDROID}" package="com.example.synthetic">
          <application>
            <meta-data android:name="QQ_APP_ID" android:value="123456" />
            <meta-data android:name="WX_APP_ID" android:value="wx0123456789abcdef" />
            <activity android:name=".Main"><intent-filter>
              <data android:scheme="https" android:host="public.example.com" />
            </intent-filter></activity>
          </application>
        </manifest>'''
        apk = self.apk([
            ("AndroidManifest.xml", manifest),
            ("assets/msdkconfig.ini", "MSDK_GAME_ID=777\nMSDK_VERSION=3.2.1\nCHANNEL_DESCRIPTION=官方渠道\n"),
        ])
        report, _ = self.run_script(apk)
        expected = {
            "package_id": "com.example.synthetic", "qq_app_id": "123456",
            "wechat_app_id": "wx0123456789abcdef", "msdk_game_id": "777",
            "msdk_version": "3.2.1", "channel_description": "官方渠道",
            "https_hosts": "public.example.com",
        }
        digest = hashlib.sha256(apk.read_bytes()).hexdigest()
        self.assertEqual(report["input"]["apk_sha256"], digest)
        for field, value in expected.items():
            self.assertEqual(report["fields"][field]["status"], "found", field)
            self.assertEqual(self.values(report, field), [value])
            evidence = report["fields"][field]["values"][0]["evidence"][0]
            self.assertEqual(evidence["apk_sha256"], digest)
            self.assertTrue(evidence["source"])
            self.assertTrue(evidence["location"])

    def test_missing_fields_are_explicit_and_binary_manifest_is_reported(self):
        apk = self.apk([
            ("AndroidManifest.xml", b"\x03\x00\x08\x00binary"),
            ("lib/arm64-v8a/libpublic.so", b"QQ_APP_ID=999999"),
            ("classes.dex", b"WX_APP_ID=wxaaaaaaaaaaaaaaaa"),
        ])
        report, _ = self.run_script(apk)
        self.assertTrue(all(field["status"] == "missing" for field in report["fields"].values()))
        self.assertIn("binary_manifest_needs_decoding", self.codes(report))

    def test_conflicts_preserve_duplicate_json_and_separate_sources(self):
        apk = self.apk([
            ("assets/config.json", '{"QQ_APP_ID":"111111","QQ_APP_ID":"222222"}'),
            ("assets/msdk.ini", "QQ_APP_ID=333333\nQQ_APP_ID=111111\n"),
        ])
        report, _ = self.run_script(apk)
        field = report["fields"]["qq_app_id"]
        self.assertEqual(field["status"], "conflict")
        self.assertEqual(set(self.values(report, "qq_app_id")), {"111111", "222222", "333333"})
        first = next(item for item in field["values"] if item["value"] == "111111")
        self.assertEqual(len(first["evidence"]), 2)

    def test_resource_reference_is_ambiguous_without_echoing_it(self):
        apk = self.apk([("AndroidManifest.xml", f'''<manifest xmlns:android="{ANDROID}" package="com.example.synthetic">
          <application><meta-data android:name="QQ_APP_ID" android:resource="@string/private_token_name" /></application>
        </manifest>''')])
        report, rendered = self.run_script(apk)
        self.assertEqual(report["fields"]["qq_app_id"]["status"], "ambiguous")
        self.assertEqual(self.values(report, "qq_app_id"), [])
        self.assertNotIn("private_token_name", rendered)

    def test_xml_evidence_uses_stable_child_positions_even_after_private_subtree(self):
        decoded = self.decoded([("res/values/config.xml", '''<resources>
          <credentials><nested><string name="qq_app_id">999999</string></nested></credentials>
          <string name="qq_app_id">123456</string>
        </resources>''')])
        report, _ = self.run_script(decoded)
        field = report["fields"]["qq_app_id"]
        self.assertEqual(self.values(report, "qq_app_id"), ["123456"])
        self.assertEqual(field["values"][0]["evidence"][0]["location"], "xml:/1/2")

    def test_invalid_compressed_stream_produces_only_static_diagnostics(self):
        apk = self.apk([
            ("assets/broken.ini", "QQ_APP_ID=999999\n"),
            ("assets/good.ini", "MSDK_GAME_ID=777\n"),
        ], compression=zipfile.ZIP_DEFLATED)
        data = bytearray(apk.read_bytes())
        name_size, extra_size = struct.unpack_from("<HH", data, 26)
        data[30 + name_size + extra_size] = 0x07  # Reserved DEFLATE block type.
        apk.write_bytes(data)
        report, rendered = self.run_script(apk)
        self.assertIn("archive_entry_unreadable", self.codes(report))
        self.assertEqual(self.values(report, "msdk_game_id"), ["777"])
        self.assertNotIn("999999", rendered)

    def test_sensitive_keys_values_containers_and_raw_lines_are_never_echoed(self):
        apk = self.apk([
            ("assets/msdk.ini", "QQ_APP_ID=123456\nMSDK_APP_KEY=SECRET_SENTINEL_ALPHA\nSDK_SECRET=SECRET_SENTINEL_BETA\n[credentials]\nQQ_APP_ID=999999\n"),
            ("assets/config.json", json.dumps({
                "secret": {"QQ_APP_ID": "888888", "MSDK_VERSION": "secret-value"},
                "MSDK_GAME_ID": "777", "access_token": "SECRET_SENTINEL_GAMMA",
                "PUBLIC_HTTPS_HOSTS": ["https://public.example.com/path?token=SECRET_SENTINEL_DELTA"],
            })),
            ("res/values/strings.xml", '<resources><string name="wechat_app_id">wx0123456789abcdef</string><string name="app_secret">SECRET_SENTINEL_EPSILON</string></resources>'),
        ])
        report, rendered = self.run_script(apk)
        for forbidden in ("SECRET_SENTINEL", "MSDK_APP_KEY", "SDK_SECRET", "access_token", "app_secret", "secret-value", "999999", "888888", "QQ_APP_ID=123456", "?token=", "/path"):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(self.values(report, "qq_app_id"), ["123456"])
        self.assertEqual(self.values(report, "https_hosts"), ["public.example.com"])

    def assert_only_public_container_values(self, report, rendered):
        self.assertEqual(self.values(report, "qq_app_id"), ["123456"])
        self.assertEqual(self.values(report, "channel_description"), ["public_channel"])
        self.assertNotIn("synthetic_private_value", rendered)
        self.assertNotIn('"999999"', rendered)
        for alias in PRIVATE_CONTAINER_NAMES:
            self.assertNotIn(alias, rendered)

    def test_sdk_key_cookie_authcode_and_client_sign_json_containers_are_skipped(self):
        config = {
            alias: {"CHANNEL_DESCRIPTION": "synthetic_private_value", "QQ_APP_ID": "999999"}
            for alias in PRIVATE_CONTAINER_NAMES
        }
        config["public"] = {"QQ_APP_ID": "123456", "CHANNEL_DESCRIPTION": "public_channel"}
        apk = self.apk([("assets/config.json", json.dumps(config))])
        report, rendered = self.run_script(apk)
        self.assert_only_public_container_values(report, rendered)

    def test_sdk_key_cookie_authcode_and_client_sign_ini_sections_are_skipped(self):
        config = "".join(
            f"[{alias}]\nCHANNEL_DESCRIPTION=synthetic_private_value\nQQ_APP_ID=999999\n"
            for alias in PRIVATE_CONTAINER_NAMES
        )
        config += "[public]\nQQ_APP_ID=123456\nCHANNEL_DESCRIPTION=public_channel\n"
        apk = self.apk([("assets/config.ini", config)])
        report, rendered = self.run_script(apk)
        self.assert_only_public_container_values(report, rendered)

    def test_sdk_key_cookie_authcode_and_client_sign_xml_containers_are_skipped(self):
        private_fields = '<string name="CHANNEL_DESCRIPTION">synthetic_private_value</string><string name="QQ_APP_ID">999999</string>'
        config = "<resources>" + "".join(
            f'<{alias}>{private_fields}</{alias}><container name="{alias}">{private_fields}</container>'
            for alias in PRIVATE_CONTAINER_NAMES
        )
        config += '<string name="QQ_APP_ID">123456</string><string name="CHANNEL_DESCRIPTION">public_channel</string></resources>'
        apk = self.apk([("res/values/config.xml", config)])
        report, rendered = self.run_script(apk)
        self.assert_only_public_container_values(report, rendered)

    def private_path_fixtures(self):
        private_config = "CHANNEL_DESCRIPTION=synthetic_private_value\nQQ_APP_ID=999999\n"
        files = [(f"assets/{alias}/config.ini", private_config) for alias in PRIVATE_CONTAINER_NAMES]
        files.extend((f"assets/{alias}.ini", private_config) for alias in PRIVATE_CONTAINER_NAMES)
        files.append(("assets/public.ini", "QQ_APP_ID=123456\nCHANNEL_DESCRIPTION=public_channel\n"))
        return files

    def test_sdk_key_cookie_authcode_and_client_sign_archive_paths_are_skipped(self):
        report, rendered = self.run_script(self.apk(self.private_path_fixtures()))
        self.assert_only_public_container_values(report, rendered)

    def test_sdk_key_cookie_authcode_and_client_sign_decoded_paths_are_skipped(self):
        report, rendered = self.run_script(self.decoded(self.private_path_fixtures()))
        self.assert_only_public_container_values(report, rendered)

    def test_generic_app_id_is_not_assigned_to_a_provider(self):
        apk = self.apk([("assets/config.ini", "APP_ID=123456\nGAME_ID=987654\n")])
        report, _ = self.run_script(apk)
        self.assertEqual(report["fields"]["qq_app_id"]["status"], "missing")
        self.assertEqual(report["fields"]["msdk_game_id"]["status"], "missing")

    def test_archive_path_traversal_is_skipped(self):
        apk = self.apk([
            ("../outside.ini", "QQ_APP_ID=999999\n"),
            ("C:/absolute.ini", "QQ_APP_ID=888888\n"),
            ("assets\\alternate.ini", "QQ_APP_ID=777777\n"),
            ("assets/good.ini", "QQ_APP_ID=123456\n"),
        ])
        # Windows ZipInfo normalizes separators while creating archives. Mutate
        # both equal-length ZIP header names to exercise the original raw path.
        apk.write_bytes(apk.read_bytes().replace(b"assets/alternate.ini", b"assets\\alternate.ini"))
        report, rendered = self.run_script(apk)
        self.assertEqual(self.values(report, "qq_app_id"), ["123456"])
        self.assertIn("unsafe_archive_path", self.codes(report))
        self.assertNotIn("../outside.ini", rendered)
        self.assertFalse((self.root / "outside.ini").exists())

    def test_duplicate_archive_entries_are_all_skipped(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            apk = self.apk([
                ("assets/config.ini", "QQ_APP_ID=999999\n"),
                ("assets/config.ini", "QQ_APP_ID=888888\n"),
                ("assets/good.ini", "MSDK_GAME_ID=777\n"),
            ])
        report, rendered = self.run_script(apk)
        self.assertEqual(self.values(report, "qq_app_id"), [])
        self.assertEqual(self.values(report, "msdk_game_id"), ["777"])
        self.assertIn("duplicate_archive_entry", self.codes(report))
        self.assertNotIn("999999", rendered)

    def test_decoded_directory_symlinks_are_not_followed(self):
        decoded = self.decoded([("assets/good.ini", "MSDK_GAME_ID=777\n")])
        outside = self.root / "outside.ini"
        outside.write_text("QQ_APP_ID=999999\n", encoding="utf-8")
        try:
            (decoded / "assets" / "linked.ini").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("This account cannot create symbolic links")
        report, _ = self.run_script(decoded)
        self.assertEqual(self.values(report, "qq_app_id"), [])
        self.assertIn("directory_link_skipped", self.codes(report))

    def test_size_limit_skips_large_stored_config(self):
        apk = self.apk([("assets/large.ini", "QQ_APP_ID=999999\n" + "#" * (1024 * 1024))])
        report, rendered = self.run_script(apk)
        self.assertIn("text_file_size_exceeded", self.codes(report))
        self.assertNotIn("999999", rendered)

    def test_successful_output_is_a_new_identical_utf8_report(self):
        apk = self.apk([("assets/msdk.ini", "CHANNEL_DESCRIPTION=官方渠道\n")])
        output = self.root / "report.json"
        report, _ = self.run_script(apk, "--output", output)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
        self.assertEqual(self.values(report, "channel_description"), ["官方渠道"])
        before = output.read_bytes()
        report, _ = self.run_script(apk, "--output", output, expected=2)
        self.assertEqual(report["error"]["code"], "output_exists")
        self.assertEqual(output.read_bytes(), before)

    def test_decompression_abuse_is_rejected_before_read(self):
        apk = self.apk([
            ("assets/bomb.ini", "QQ_APP_ID=999999\n" + "#" * 700000),
            ("assets/good.ini", "QQ_APP_ID=123456\n"),
        ], compression=zipfile.ZIP_DEFLATED)
        report, _ = self.run_script(apk)
        self.assertEqual(self.values(report, "qq_app_id"), ["123456"])
        self.assertIn("compression_ratio_exceeded", self.codes(report))

    def test_decoded_directory_provenance_and_optional_original_apk(self):
        decoded = self.decoded([("assets/msdk.ini", "QQ_APP_ID=123456\n")])
        report, _ = self.run_script(decoded)
        self.assertIsNone(report["input"]["apk_sha256"])
        self.assertIn("apk_digest_unavailable", self.codes(report))
        original = self.apk([("assets/msdk.ini", "QQ_APP_ID=123456\n")])
        report, _ = self.run_script(decoded, "--apk-source", original)
        self.assertEqual(report["input"]["apk_sha256"], hashlib.sha256(original.read_bytes()).hexdigest())
        self.assertIn("decoded_to_apk_link_unverified", self.codes(report))

    def test_xml_entities_are_not_expanded(self):
        apk = self.apk([("res/values/strings.xml", '''<!DOCTYPE resources [<!ENTITY unsafe "SECRET_SENTINEL_ENTITY">]>
          <resources><string name="msdk_version">&unsafe;</string></resources>''')])
        report, rendered = self.run_script(apk)
        self.assertIn("xml_dtd_or_entity_forbidden", self.codes(report))
        self.assertNotIn("SECRET_SENTINEL_ENTITY", rendered)
        self.assertEqual(report["fields"]["msdk_version"]["status"], "missing")

    def test_local_hosts_userinfo_and_invalid_values_are_not_reported(self):
        apk = self.apk([("assets/config.json", json.dumps({
            "PUBLIC_HTTPS_HOSTS": ["https://127.0.0.1/x", "https://localhost", "https://intranet.local", "https://user:SECRET_SENTINEL_HOST@public.example.com", "https://public.example.com/x"],
            "QQ_APP_ID": "SECRET_SENTINEL_BAD_ID",
        }))])
        report, rendered = self.run_script(apk)
        self.assertEqual(self.values(report, "https_hosts"), ["public.example.com"])
        self.assertEqual(report["fields"]["qq_app_id"]["status"], "ambiguous")
        self.assertNotIn("SECRET_SENTINEL", rendered)
        self.assertNotIn("127.0.0.1", rendered)

    def test_malformed_config_error_does_not_leak_input(self):
        apk = self.apk([("assets/config.json", '{"SDK_SECRET":"SECRET_SENTINEL_MALFORMED",')])
        report, rendered = self.run_script(apk)
        self.assertIn("malformed_json", self.codes(report))
        self.assertNotIn("SECRET_SENTINEL", rendered)

    def test_output_path_cannot_overwrite_input_or_decoded_sources(self):
        decoded = self.decoded([("assets/msdk.ini", "QQ_APP_ID=123456\n")])
        source = decoded / "assets" / "msdk.ini"
        before = source.read_bytes()
        report, _ = self.run_script(decoded, "--output", source, expected=2)
        self.assertEqual(report["error"]["code"], "output_overlaps_input")
        self.assertEqual(source.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
