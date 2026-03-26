"""Extended tests for intel modules to reach 80%+ coverage."""

from __future__ import annotations

import socket
from unittest.mock import patch, MagicMock

import pytest

from src.core.config import AppConfig
from src.intel.dns_lookup import reverse_dns, forward_dns
from src.intel.whois_lookup import whois_lookup, _try_whois_command, _try_nslookup_fallback
from src.intel.geoip import geoip_lookup
from src.intel.osint import abuseipdb_check, virustotal_check
from src.intel.intel_aggregator import gather_intel
from src.intel.traceroute import traceroute


# ---------------------------------------------------------------------------
# DNS extended
# ---------------------------------------------------------------------------

class TestDnsLookupExtended:
    """Extended DNS tests covering timeout and gaierror."""

    @patch("socket.gethostbyaddr", side_effect=socket.gaierror("lookup failed"))
    def test_reverse_dns_gaierror(self, mock: MagicMock) -> None:
        result = reverse_dns("1.2.3.4")
        assert result == []

    @patch("socket.gethostbyaddr", side_effect=socket.timeout("timed out"))
    def test_reverse_dns_timeout(self, mock: MagicMock) -> None:
        result = reverse_dns("1.2.3.4")
        assert result == []

    @patch("socket.getaddrinfo")
    def test_forward_dns_success(self, mock_getaddrinfo: MagicMock) -> None:
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("5.6.7.8", 0)),
        ]
        result = forward_dns("example.com")
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    @patch("socket.getaddrinfo", side_effect=socket.gaierror("fail"))
    def test_forward_dns_gaierror(self, mock: MagicMock) -> None:
        result = forward_dns("bad.example.com")
        assert result == []

    @patch("socket.getaddrinfo", side_effect=socket.timeout("timeout"))
    def test_forward_dns_timeout(self, mock: MagicMock) -> None:
        result = forward_dns("slow.example.com")
        assert result == []


# ---------------------------------------------------------------------------
# WHOIS extended
# ---------------------------------------------------------------------------

class TestWhoisExtended:
    """Extended WHOIS tests for all code paths."""

    @patch("subprocess.run")
    def test_whois_command_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="OrgName:        Google LLC\nCountry:        US\n",
        )
        result = whois_lookup("8.8.8.8")
        assert result["organization"] == "Google LLC"
        assert result["country"] == "US"

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_whois_command_not_found_fallback(self, mock_run: MagicMock) -> None:
        # Falls back to nslookup
        with patch("subprocess.run") as mock_nslookup:
            mock_nslookup.side_effect = [
                FileNotFoundError,  # whois not found
                MagicMock(returncode=0, stdout="Server: ns1\n"),  # nslookup
            ]
            result = whois_lookup("8.8.8.8")
            assert result["ip_address"] == "8.8.8.8"

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_nslookup_fallback_not_found(self, mock: MagicMock) -> None:
        result = _try_nslookup_fallback("1.2.3.4")
        assert result["ip_address"] == "1.2.3.4"
        assert result["organization"] is None

    @patch("subprocess.run")
    def test_whois_timeout(self, mock_run: MagicMock) -> None:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="whois", timeout=15)
        result = _try_whois_command("1.2.3.4")
        assert result is None

    @patch("subprocess.run")
    def test_whois_command_nonzero_return(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        result = _try_whois_command("1.2.3.4")
        assert result is None

    @patch("subprocess.run")
    def test_nslookup_fallback_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="Name: example.com\nAddress: 1.2.3.4\n")
        result = _try_nslookup_fallback("1.2.3.4")
        assert result["raw"] != ""

    @patch("subprocess.run")
    def test_nslookup_timeout(self, mock_run: MagicMock) -> None:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nslookup", timeout=10)
        result = _try_nslookup_fallback("1.2.3.4")
        assert result["raw"] == ""


# ---------------------------------------------------------------------------
# GeoIP extended
# ---------------------------------------------------------------------------

class TestGeoIPExtended:
    """Extended GeoIP tests."""

    @patch("requests.get")
    def test_geoip_non_success_status(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "fail", "message": "reserved range"}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        result = geoip_lookup("10.0.0.1")
        assert result["country"] is None

    @patch("requests.get")
    def test_geoip_request_exception(self, mock_get: MagicMock) -> None:
        import requests
        mock_get.side_effect = requests.ConnectionError("fail")
        result = geoip_lookup("1.2.3.4")
        assert result["country"] is None


# ---------------------------------------------------------------------------
# OSINT extended
# ---------------------------------------------------------------------------

class TestOSINTExtended:
    """Extended OSINT tests."""

    @patch("requests.get")
    def test_virustotal_with_key(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_key_vt")
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 2,
                        "harmless": 50,
                        "undetected": 5,
                    },
                    "country": "CN",
                    "as_owner": "Evil Corp",
                    "reputation": -50,
                }
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = virustotal_check("1.2.3.4")
        assert result["available"] is True
        assert result["malicious"] == 10
        assert result["country"] == "CN"

    @patch("requests.get")
    def test_abuseipdb_request_error(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
        import requests
        mock_get.side_effect = requests.ConnectionError("fail")
        result = abuseipdb_check("1.2.3.4")
        assert result["available"] is False
        assert "error" in result

    @patch("requests.get")
    def test_virustotal_request_error(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "key")
        import requests
        mock_get.side_effect = requests.Timeout("timeout")
        result = virustotal_check("1.2.3.4")
        assert result["available"] is False


# ---------------------------------------------------------------------------
# Traceroute extended
# ---------------------------------------------------------------------------

class TestTracerouteExtended:
    """Extended traceroute tests."""

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_tracert_not_found(self, mock: MagicMock) -> None:
        result = traceroute("8.8.8.8")
        assert result == []

    @patch("subprocess.run")
    def test_tracert_timeout(self, mock_run: MagicMock) -> None:
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="tracert", timeout=60)
        result = traceroute("8.8.8.8")
        assert result == []

    @patch("subprocess.run")
    def test_tracert_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Tracing route to 8.8.8.8\n"
                "\n"
                "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
                "  2    10 ms     9 ms    11 ms  10.0.0.1\n"
                "  3     *        *        *     Request timed out.\n"
                "  4    20 ms    19 ms    21 ms  8.8.8.8\n"
            ),
        )
        result = traceroute("8.8.8.8")
        assert len(result) == 4
        assert result[0]["ip"] == "192.168.1.1"
        assert result[2]["timeout"] is True
        assert result[3]["ip"] == "8.8.8.8"


# ---------------------------------------------------------------------------
# Intel aggregator extended
# ---------------------------------------------------------------------------

class TestIntelAggregatorExtended:
    """Extended intel_aggregator tests."""

    @patch("src.intel.intel_aggregator.reverse_dns", return_value=["host.example.com"])
    @patch("src.intel.intel_aggregator.whois_lookup", return_value={
        "organization": "Test Org", "country": "US", "raw": "whois data"
    })
    @patch("src.intel.intel_aggregator.geoip_lookup", return_value={
        "country": "United States", "city": "NYC", "latitude": 40.7, "longitude": -74.0
    })
    @patch("src.intel.intel_aggregator.traceroute", return_value=[
        {"hop": 1, "ip": "192.168.1.1", "rtts": ["1ms"]}
    ])
    def test_gather_intel_all_sources(
        self, mock_trace: MagicMock, mock_geo: MagicMock,
        mock_whois: MagicMock, mock_dns: MagicMock,
        test_config: AppConfig,
    ) -> None:
        result = gather_intel("203.0.113.50", test_config)
        assert result.ip_address == "203.0.113.50"
        assert result.reverse_dns == ["host.example.com"]
        assert result.whois_org == "Test Org"
        assert result.geoip_country == "United States"
        assert len(result.traceroute_hops) == 1

    @patch("src.intel.intel_aggregator.reverse_dns", side_effect=Exception("DNS fail"))
    @patch("src.intel.intel_aggregator.whois_lookup", side_effect=Exception("WHOIS fail"))
    @patch("src.intel.intel_aggregator.geoip_lookup", side_effect=Exception("GeoIP fail"))
    @patch("src.intel.intel_aggregator.traceroute", side_effect=Exception("Trace fail"))
    def test_gather_intel_all_failures_graceful(
        self, mock_trace: MagicMock, mock_geo: MagicMock,
        mock_whois: MagicMock, mock_dns: MagicMock,
        test_config: AppConfig,
    ) -> None:
        result = gather_intel("1.2.3.4", test_config)
        assert result.ip_address == "1.2.3.4"
        assert result.reverse_dns == []
        assert result.whois_org is None
