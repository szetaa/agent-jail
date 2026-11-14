"""Tests for forward proxy domain allowlisting and SSRF protection."""

import asyncio
from pathlib import Path
import tempfile

from agent_jail.proxy import is_domain_allowed, is_ip_allowed, parse_allowlist


def test_parse_allowlist():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("# Comment\n\ngithub.com\n*.pypi.org\n  api.openai.com  \n127.0.0.1:11434\n")
        f.flush()
        f_path = Path(f.name)

    try:
        patterns = parse_allowlist(f_path)
        assert patterns == ["github.com", "*.pypi.org", "api.openai.com", "127.0.0.1:11434"]
    finally:
        f_path.unlink()


def test_is_domain_allowed():
    patterns = ["github.com", "*.pypi.org", "api.test-domain.com", "127.0.0.1:11434", "192.168.1.10:8080"]

    # Exact match
    assert is_domain_allowed("github.com", 443, patterns) is True
    assert is_domain_allowed("GITHUB.COM", 80, patterns) is True
    assert is_domain_allowed("notgithub.com", 443, patterns) is False

    # Wildcard match
    assert is_domain_allowed("pypi.org", 443, patterns) is True
    assert is_domain_allowed("files.pypi.org", 443, patterns) is True
    assert is_domain_allowed("deep.nested.files.pypi.org", 443, patterns) is True
    assert is_domain_allowed("fakepypi.org", 443, patterns) is False

    # Subdomain without wildcard
    assert is_domain_allowed("api.test-domain.com", 443, patterns) is True
    assert is_domain_allowed("test-domain.com", 443, patterns) is False

    # Host with specific port (including loopback equivalence between localhost and 127.0.0.1)
    assert is_domain_allowed("127.0.0.1", 11434, patterns) is True
    assert is_domain_allowed("localhost", 11434, patterns) is True
    assert is_domain_allowed("127.0.0.1", 8080, patterns) is False  # Wrong port
    assert is_domain_allowed("192.168.1.10", 8080, patterns) is True
    assert is_domain_allowed("192.168.1.10", 80, patterns) is False


def test_is_ip_allowed_ssrf_protection():
    empty_patterns: list[str] = []
    # Loopback
    assert is_ip_allowed("127.0.0.1", 80, empty_patterns) is False
    assert is_ip_allowed("::1", 80, empty_patterns) is False

    # Private RFC 1918
    assert is_ip_allowed("10.0.0.1", 80, empty_patterns) is False
    assert is_ip_allowed("172.16.0.1", 80, empty_patterns) is False
    assert is_ip_allowed("192.168.1.100", 80, empty_patterns) is False

    # Link-local / Cloud metadata (AWS/GCP/Azure)
    assert is_ip_allowed("169.254.169.254", 80, empty_patterns) is False

    # Multicast & Unspecified
    assert is_ip_allowed("0.0.0.0", 80, empty_patterns) is False
    assert is_ip_allowed("224.0.0.1", 80, empty_patterns) is False

    # Valid Public IP addresses
    assert is_ip_allowed("140.82.121.4", 443, empty_patterns) is True  # GitHub
    assert is_ip_allowed("151.101.1.63", 443, empty_patterns) is True   # PyPI / Fastly
    assert is_ip_allowed("8.8.8.8", 53, empty_patterns) is True        # Google DNS

    # Explicit user allowlist bypass (including localhost:port -> 127.0.0.1 / ::1)
    custom_patterns = ["localhost:11434", "192.168.1.10:8080"]
    assert is_ip_allowed("127.0.0.1", 11434, custom_patterns) is True
    assert is_ip_allowed("::1", 11434, custom_patterns) is True
    assert is_ip_allowed("127.0.0.1", 9999, custom_patterns) is False
    assert is_ip_allowed("192.168.1.10", 8080, custom_patterns) is True


def test_proxy_server_denies_blocked_domain(capsys):
    async def _async_test():
        with tempfile.NamedTemporaryFile("w+", delete=False) as f_allow:
            f_allow.write("github.com\n")
            f_allow.flush()
            allow_path = f_allow.name

        try:
            from agent_jail.proxy import handle_client

            # Simulate client connecting to blocked domain
            reader = asyncio.StreamReader()
            reader.feed_data(b"CONNECT malicious-site.com:443 HTTP/1.1\r\nHost: malicious-site.com\r\n\r\n")
            reader.feed_eof()

            class MockWriter:
                def __init__(self):
                    self.data = bytearray()
                    self.is_closed = False

                def write(self, d):
                    self.data.extend(d)

                async def drain(self):
                    pass

                def close(self):
                    self.is_closed = True

                async def wait_closed(self):
                    pass

            writer = MockWriter()
            await handle_client(reader, writer, allow_path)

            response = bytes(writer.data).decode("utf-8")
            assert "403 Forbidden" in response
            assert "malicious-site.com:443" in response
        finally:
            Path(allow_path).unlink(missing_ok=True)

    asyncio.run(_async_test())
    captured = capsys.readouterr()
    assert "Blocked CONNECT to malicious-site.com:443" in captured.err
