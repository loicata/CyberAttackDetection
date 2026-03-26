"""Tests for threat intelligence modules."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from src.core.config import AppConfig
from src.intel.dns_lookup import reverse_dns, forward_dns
from src.intel.whois_lookup import whois_lookup, _parse_whois_output
from src.intel.geoip import geoip_lookup, _empty_result
from src.intel.traceroute import traceroute, _parse_tracert_output, _looks_like_ip
from src.intel.osint import abuseipdb_check, virustotal_check
from src.intel.intel_aggregator import gather_intel, _safe_call


class TestDnsLookup:
    """Tests for DNS lookup functions."""

    def test_empty_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            reverse_dns("")

    def test_empty_hostname_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            forward_dns("")

    @patch("socket.gethostbyaddr")
    def test_reverse_dns_success(self, mock_gethostbyaddr: MagicMock) -> None:
        mock_gethostbyaddr.return_value = ("host.example.com", ["alias.example.com"], ["1.2.3.4"])
        result = reverse_dns("1.2.3.4")
        assert "host.example.com" in result
        assert "alias.example.com" in result

    @patch("socket.gethostbyaddr", side_effect=Exception("DNS error"))
    def test_reverse_dns_failure(self, mock: MagicMock) -> None:
        # Should not raise, returns empty list
        import socket
        with patch("socket.gethostbyaddr", side_effect=socket.herror("not found")):
            result = reverse_dns("1.2.3.4")
            assert result == []


class TestWhoisLookup:
    """Tests for WHOIS lookup."""

    def test_empty_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            whois_lookup("")

    def test_parse_whois_output(self) -> None:
        output = """
OrgName:        Example Corp
Country:        US
"""
        result = _parse_whois_output(output, "1.2.3.4")
        assert result["organization"] == "Example Corp"
        assert result["country"] == "US"

    def test_parse_empty_whois(self) -> None:
        result = _parse_whois_output("", "1.2.3.4")
        assert result["organization"] is None
        assert result["country"] is None


class TestGeoIP:
    """Tests for GeoIP lookup."""

    def test_empty_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            geoip_lookup("")

    def test_empty_result(self) -> None:
        result = _empty_result("1.2.3.4")
        assert result["ip_address"] == "1.2.3.4"
        assert result["country"] is None

    @patch("requests.get")
    def test_successful_lookup(self, mock_get: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "country": "United States",
            "city": "New York",
            "lat": 40.71,
            "lon": -74.01,
            "isp": "Example ISP",
            "org": "Example Org",
            "as": "AS12345",
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = geoip_lookup("8.8.8.8")
        assert result["country"] == "United States"
        assert result["city"] == "New York"


class TestTraceroute:
    """Tests for traceroute."""

    def test_empty_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            traceroute("")

    def test_invalid_max_hops_raises(self) -> None:
        with pytest.raises(ValueError, match="must be 1-64"):
            traceroute("1.2.3.4", max_hops=100)

    def test_looks_like_ip(self) -> None:
        assert _looks_like_ip("192.168.1.1") is True
        assert _looks_like_ip("not_an_ip") is False
        assert _looks_like_ip("999.999.999.999") is False

    def test_parse_tracert_output(self) -> None:
        output = """
Tracing route to 8.8.8.8

  1     1 ms     1 ms     1 ms  192.168.1.1
  2     5 ms     4 ms     5 ms  10.0.0.1
  3     *        *        *     Request timed out.
"""
        hops = _parse_tracert_output(output)
        assert len(hops) >= 2
        assert hops[0]["hop"] == 1
        assert hops[0]["ip"] == "192.168.1.1"


class TestOSINT:
    """Tests for OSINT API clients."""

    def test_abuseipdb_empty_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            abuseipdb_check("")

    def test_virustotal_empty_ip_raises(self) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            virustotal_check("")

    def test_abuseipdb_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        result = abuseipdb_check("1.2.3.4")
        assert result["available"] is False

    def test_virustotal_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        result = virustotal_check("1.2.3.4")
        assert result["available"] is False

    @patch("requests.get")
    def test_abuseipdb_with_key(
        self, mock_get: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key")
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 75,
                "totalReports": 42,
                "countryCode": "CN",
                "isp": "Evil Corp",
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = abuseipdb_check("1.2.3.4")
        assert result["available"] is True
        assert result["abuse_confidence_score"] == 75


class TestIntelAggregator:
    """Tests for intel_aggregator."""

    def test_empty_ip_raises(self, test_config: AppConfig) -> None:
        with pytest.raises(ValueError, match="must not be empty"):
            gather_intel("", test_config)

    def test_safe_call_catches_exceptions(self) -> None:
        def failing_func() -> None:
            raise RuntimeError("fail")

        result = _safe_call("test", failing_func)
        assert result == {}

    def test_safe_call_returns_result(self) -> None:
        result = _safe_call("test", lambda: [1, 2, 3])
        assert result == [1, 2, 3]
