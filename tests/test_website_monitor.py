import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import requests

import website_monitor as monitor


class URLTests(unittest.TestCase):
    def test_adds_https_when_scheme_is_missing(self):
        normalized, error = monitor.normalize_url("example.com/path")
        self.assertIsNone(error)
        self.assertEqual(normalized, "https://example.com/path")

    def test_rejects_unsupported_scheme(self):
        normalized, error = monitor.normalize_url("ftp://example.com")
        self.assertIsNone(normalized)
        self.assertIn("Only http:// and https://", error)

    def test_rejects_malformed_port(self):
        normalized, error = monitor.normalize_url("https://example.com:bad")
        self.assertIsNone(normalized)
        self.assertIn("Invalid URL", error)


class ParsingTests(unittest.TestCase):
    def test_parses_rdap_expiration_event(self):
        expiration = monitor._parse_rdap_datetime("2030-05-10T12:30:00Z")
        self.assertEqual(expiration, datetime(2030, 5, 10, 12, 30, tzinfo=timezone.utc))

    def test_parses_date_only(self):
        expiration = monitor._parse_rdap_datetime("2030-05-10")
        self.assertEqual(expiration, datetime(2030, 5, 10, tzinfo=timezone.utc))

    def test_detects_hosting_indicators(self):
        found = monitor.detect_hosting_indicators("Sorry, this account has been suspended by the provider.")
        self.assertIn("Possible hosting/account suspension page", found)

    def test_does_not_flag_generic_word_suspended(self):
        self.assertEqual(monitor.detect_hosting_indicators("The user suspended the animation."), [])


class SSLTests(unittest.TestCase):
    @patch("website_monitor.socket.create_connection", side_effect=socket.timeout("timed out"))
    def test_ssl_check_failure_is_handled(self, _mock_connection):
        status, expiration, days, error = monitor.check_ssl_certificate("example.test", 443, monitor.CheckConfig())
        self.assertEqual(status, "CHECK_FAILED")
        self.assertEqual(expiration, "Unknown")
        self.assertEqual(days, "N/A")
        self.assertIn("SSL check failed", error)


    def test_ip_network_lookup_skips_reserved_addresses(self):
        session = MagicMock(spec=requests.Session)
        value = monitor.lookup_ip_network_info("127.0.0.1", session, monitor.CheckConfig())
        self.assertIn("Private/reserved", value)
        session.get.assert_not_called()

class MonitoringTests(unittest.TestCase):
    def _result(self, status="WORKING"):
        return monitor.WebsiteResult(
            website="https://example.com",
            checked_at="2026-11-09T08:00:00+06:00",
            normalized_url="https://example.com/",
            final_url="https://example.com/",
            http_status="200",
            availability="AVAILABLE",
            content_type="text/html",
            dns_status="RESOLVED",
            resolved_ips="203.0.113.10",
            domain="example.com",
            domain_expiration="2030-01-01 00:00 UTC",
            domain_days_remaining=1000,
            rdap_status="FOUND",
            ssl_status="VALID",
            ssl_expires_at="2027-01-01 00:00 UTC",
            ssl_days_remaining=53,
            final_status=status,
        )

    @patch("website_monitor.check_website")
    def test_one_unexpected_failure_does_not_stop_other_urls(self, mock_check):
        mock_check.side_effect = [RuntimeError("unexpected test failure"), self._result()]
        results = monitor.check_all_websites(
            ["https://first.example", "https://second.example"],
            MagicMock(spec=requests.Session),
            monitor.CheckConfig(),
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].final_status, "UNABLE_TO_VERIFY")
        self.assertEqual(results[1].final_status, "WORKING")

    @patch("website_monitor.lookup_domain_expiration", return_value=("NO_EXPIRATION_DATA", "Not published", "N/A", None))
    @patch("website_monitor.resolve_dns", return_value=("RESOLVED", ["203.0.113.10"], None))
    @patch("website_monitor.check_ssl_certificate", return_value=("VALID", "2027-01-01 00:00 UTC", 53, None))
    def test_html_homepage_is_marked_working(self, _ssl, _dns, _rdap):
        response = MagicMock()
        response.status_code = 200
        response.url = "https://example.com/"
        response.headers = {"Content-Type": "text/html; charset=utf-8"}
        response.text = "<!doctype html><html><body>Hello</body></html>"
        response.history = []
        session = MagicMock(spec=requests.Session)
        session.get.return_value = response

        result = monitor.check_website("https://example.com", session, monitor.CheckConfig())
        self.assertEqual(result.availability, "AVAILABLE")
        self.assertEqual(result.content_type, "text/html")
        self.assertEqual(result.final_status, "WORKING")

    @patch("website_monitor.lookup_domain_expiration", return_value=("NO_EXPIRATION_DATA", "Not published", "N/A", None))
    @patch("website_monitor.resolve_dns", return_value=("RESOLVED", ["203.0.113.10"], None))
    @patch("website_monitor.check_ssl_certificate", return_value=("VALID", "2027-01-01 00:00 UTC", 53, None))
    def test_server_error_is_marked_down(self, _ssl, _dns, _rdap):
        response = MagicMock()
        response.status_code = 503
        response.url = "https://example.com/"
        response.headers = {"Content-Type": "text/html"}
        response.text = "Service unavailable"
        response.history = []
        session = MagicMock(spec=requests.Session)
        session.get.return_value = response

        result = monitor.check_website("https://example.com", session, monitor.CheckConfig())
        self.assertEqual(result.final_status, "DOWN")


    @patch("website_monitor.lookup_domain_expiration", return_value=("NO_EXPIRATION_DATA", "Not published", "N/A", None))
    @patch("website_monitor.resolve_dns", return_value=("RESOLVED", ["203.0.113.10"], None))
    @patch("website_monitor.check_ssl_certificate", return_value=("VALID", "2027-01-01 00:00 UTC", 53, None))
    def test_http_timeout_is_marked_down(self, _ssl, _dns, _rdap):
        session = MagicMock(spec=requests.Session)
        session.get.side_effect = requests.exceptions.Timeout("simulated timeout")

        result = monitor.check_website("https://example.com", session, monitor.CheckConfig())
        self.assertEqual(result.availability, "TIMEOUT")
        self.assertEqual(result.final_status, "DOWN")

    @patch("website_monitor.lookup_domain_expiration", return_value=("NO_EXPIRATION_DATA", "Not published", "N/A", None))
    @patch("website_monitor.resolve_dns", return_value=("RESOLVED", ["203.0.113.10"], None))
    @patch("website_monitor.check_ssl_certificate", return_value=("VALID", "2027-01-01 00:00 UTC", 53, None))
    def test_hosting_suspension_message_is_potential_expiration(self, _ssl, _dns, _rdap):
        response = MagicMock()
        response.status_code = 200
        response.url = "https://example.com/"
        response.headers = {"Content-Type": "text/html"}
        response.text = "<html><body>This account has been suspended.</body></html>"
        response.history = []
        session = MagicMock(spec=requests.Session)
        session.get.return_value = response

        result = monitor.check_website("https://example.com", session, monitor.CheckConfig())
        self.assertEqual(result.final_status, "POTENTIAL_EXPIRATION")
        self.assertTrue(result.hosting_indicators)

    def test_invalid_url_is_unable_to_verify(self):
        result = monitor.check_website("ftp://example.com", MagicMock(spec=requests.Session), monitor.CheckConfig())
        self.assertEqual(result.final_status, "UNABLE_TO_VERIFY")
        self.assertEqual(result.availability, "INVALID_URL")


    def test_local_fixture_server_and_cli_generate_daily_reports(self):
        class FixtureHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = ("<html><body>OK</body></html>" if self.path == "/ok" else "<html><body>Unavailable</body></html>").encode()
                self.send_response(200 if self.path == "/ok" else 503)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                return

        server = HTTPServer(("127.0.0.1", 0), FixtureHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                urls_file = root / "urls.txt"
                urls_file.write_text(
                    f"http://127.0.0.1:{server.server_port}/ok\n"
                    f"http://127.0.0.1:{server.server_port}/error\n",
                    encoding="utf-8",
                )
                exit_code = monitor.main([
                    "--urls-file", str(urls_file),
                    "--reports-dir", str(root / "reports"),
                    "--logs-dir", str(root / "logs"),
                ])
                self.assertEqual(exit_code, 0)
                csv_files = list((root / "reports").glob("*.csv"))
                html_files = list((root / "reports").glob("*.html"))
                self.assertEqual(len(csv_files), 1)
                self.assertEqual(len(html_files), 1)
                with csv_files[0].open(encoding="utf-8-sig", newline="") as file:
                    rows = list(csv.DictReader(file))
                self.assertEqual(len(rows), 2)
                self.assertEqual(rows[0]["HTTP Status"], "200")
                self.assertEqual(rows[0]["Final Status"], "WARNING")  # HTTP-only homepage
                self.assertEqual(rows[1]["HTTP Status"], "503")
                self.assertEqual(rows[1]["Final Status"], "DOWN")
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    def test_csv_and_html_reports_are_created(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            results = [self._result()]
            now = datetime(2026, 11, 9, 8, 49, tzinfo=timezone(timedelta(hours=6)))
            csv_path, html_path = monitor.write_reports(results, Path(temp_dir), now)
            self.assertTrue(csv_path.exists())
            self.assertTrue(html_path.exists())
            self.assertEqual(csv_path.name, "website_report_2026-11-09.csv")
            self.assertEqual(html_path.name, "website_report_2026-11-09.html")
            with csv_path.open(encoding="utf-8-sig", newline="") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["Final Status"], "WORKING")
            self.assertIn("Website Availability and Hosting Monitor", html_path.read_text(encoding="utf-8"))

    def test_second_run_does_not_overwrite_first_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            results = [self._result()]
            now = datetime(2026, 11, 9, 8, 49, tzinfo=timezone(timedelta(hours=6)))
            first = monitor.write_reports(results, Path(temp_dir), now)
            second = monitor.write_reports(results, Path(temp_dir), now)
            self.assertNotEqual(first[0], second[0])
            self.assertNotEqual(first[1], second[1])
            self.assertTrue(first[0].exists())
            self.assertTrue(second[0].exists())

    def test_load_urls_skips_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "urls.txt"
            path.write_text("# comment\n\nexample.com\nhttps://example.org\n", encoding="utf-8")
            self.assertEqual(monitor.load_urls(path), ["example.com", "https://example.org"])


if __name__ == "__main__":
    unittest.main()
