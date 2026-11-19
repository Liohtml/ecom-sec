"""Offline regression tests for the daily advisory sync; Python stdlib only."""
import contextlib
import datetime as dt
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "advisory_sync"
SPEC = importlib.util.spec_from_file_location("advisory_sync", ROOT / "scripts" / "advisory_sync.py")
sync = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync)


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


class AdvisorySyncTests(unittest.TestCase):
    def test_nvd_parses_ranges_and_dates(self):
        errors = []
        with mock.patch.object(sync, "nvd_search", return_value=[fixture("nvd_response.json")["vulnerabilities"][0]["cve"]]):
            result = sync.nvd_candidates(
                "shopware6", sync.PLATFORMS["shopware6"],
                dt.datetime(2099, 1, 1), dt.datetime(2099, 1, 4), None, errors,
            )
        self.assertEqual(errors, [])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["affected"], [">=6.5.0.0 <6.5.8.0"])
        self.assertEqual(result[0]["fixed_in"], ["6.5.8.0"])
        self.assertEqual(result[0]["published"], "2099-01-02")

    def test_osv_alias_and_component_version_mapping(self):
        errors = []
        with mock.patch.object(sync, "http_json", return_value=fixture("osv_response.json")):
            result = sync.osv_candidates(
                "shopware6", sync.PLATFORMS["shopware6"],
                dt.datetime(2099, 1, 1, tzinfo=dt.UTC), errors,
            )
        self.assertEqual(errors, [])
        self.assertEqual(result[0]["id"], "CVE-2099-0001")
        self.assertIn("GHSA-xxxx-yyyy-zzzz", result[0]["aliases"])
        self.assertEqual(result[0]["affected"], [">=6.5.0.0 <6.5.8.0"])

    def test_rate_limit_error_is_observable(self):
        errors = []
        with mock.patch.object(sync, "nvd_search", side_effect=RuntimeError("429")):
            result = sync.nvd_candidates(
                "shopware6", sync.PLATFORMS["shopware6"],
                dt.datetime(2099, 1, 1), dt.datetime(2099, 1, 4), None, errors,
            )
        self.assertEqual(result, [])
        self.assertTrue(any("429" in error for error in errors))

    def test_kev_failure_can_fail_closed(self):
        errors = []
        with mock.patch.object(sync, "http_json", side_effect=RuntimeError("offline")):
            self.assertEqual(sync.kev_index(errors), {})
        self.assertEqual(len(errors), 1)

    def test_end_to_end_writes_metadata_and_inactive_draft(self):
        state = {"kev": False}

        def fake_http(url, data=None, headers=None, retries=4):
            if "cisa.gov" in url:
                if state["kev"]:
                    return {"vulnerabilities": [{"cveID": "CVE-2099-0001", "dateAdded": "2099-01-03"}]}
                return {"vulnerabilities": []}
            if data is not None:
                return fixture("osv_response.json")
            return fixture("nvd_response.json")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "candidates.json"
            argv = ["advisory_sync.py", "--out", str(output), "--require-all-sources"]
            with (
                mock.patch.object(sync, "http_json", side_effect=fake_http),
                mock.patch.object(sync, "nvd_search", return_value=[fixture("nvd_response.json")["vulnerabilities"][0]["cve"]]),
                mock.patch.object(sync, "load_known", return_value=(set(), set())),
                mock.patch.object(sync, "write_drafts", wraps=sync.write_drafts),
                mock.patch.object(sync.dt, "datetime", wraps=dt.datetime) as clock,
                mock.patch("sys.argv", argv),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                clock.now.return_value = dt.datetime(2099, 1, 4, tzinfo=dt.UTC)
                clock.fromisoformat = dt.datetime.fromisoformat
                self.assertEqual(sync.main(), 0)
            document = json.loads(output.read_text())
            self.assertTrue(document["metadata"]["complete"])
            self.assertTrue(document["metadata"]["sources"]["cisa_kev"]["available"])
            self.assertEqual(document["metadata"]["window"]["days"], 3)
            self.assertEqual(document["metadata"]["counts"]["candidates"], 1)
            self.assertEqual(len(document["candidates"]), 1)
            self.assertEqual(document["candidates"][0]["sources"], ["nvd", "osv"])

    def test_main_fails_on_source_failure_when_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "candidates.json"
            argv = ["advisory_sync.py", "--out", str(output), "--no-drafts", "--require-all-sources"]
            with (
                mock.patch.object(sync, "kev_index", side_effect=lambda errors: errors.append("CISA KEV: down") or {}),
                mock.patch.object(sync, "nvd_candidates", side_effect=lambda *args: args[-1].append("NVD down") or []),
                mock.patch.object(sync, "osv_candidates", return_value=[]),
                mock.patch.object(sync, "load_known", return_value=(set(), set())),
                mock.patch("sys.argv", argv),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(sync.main(), 1)
            self.assertFalse(json.loads(output.read_text())["metadata"]["complete"])


if __name__ == "__main__":
    unittest.main()
