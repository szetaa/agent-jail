#!/usr/bin/env python3
"""Lightweight, zero-dependency async forward proxy with domain allowlisting and SSRF protection.

Runs outside the sandbox on 127.0.0.1 to route approved outbound traffic.
"""

from __future__ import annotations

import argparse
import asyncio
import fnmatch
import ipaddress
import os
from pathlib import Path
import socket
import sys
from urllib.parse import urlparse


def parse_allowlist(path: str | Path) -> list[str]:
    """Parse allowlist file, ignoring comments and blank lines."""
    patterns: list[str] = []
    if not path or not os.path.exists(path):
        return patterns

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line.lower())
    except Exception:
        pass
    return patterns


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def is_domain_allowed(host: str, port: int, patterns: list[str]) -> bool:
    """Check if host:port matches any pattern in the allowlist.

    Patterns can be:
    - Hostname / wildcard: 'github.com', '*.github.com'
    - Hostname with port: '127.0.0.1:11434', 'localhost:8080', '127.0.0.1:4000'
    - IP address: '192.168.1.10'
    """
    host = host.lower().strip(".")
    for pattern in patterns:
        pattern = pattern.lower().strip()
        if not pattern:
            continue

        # Check if pattern specifies a port (e.g., "127.0.0.1:11434")
        if ":" in pattern:
            pat_host, pat_port_str = pattern.rsplit(":", 1)
            try:
                pat_port = int(pat_port_str)
            except ValueError:
                continue

            if port == pat_port:
                pat_host_clean = pat_host.strip(".")
                if (
                    host == pat_host_clean
                    or fnmatch.fnmatch(host, pat_host_clean)
                    or (host in LOOPBACK_HOSTS and pat_host_clean in LOOPBACK_HOSTS)
                ):
                    return True
        else:
            # Pattern is host-only (matches any port)
            if pattern.startswith("*."):
                base = pattern[2:]
                if host == base or host.endswith("." + base):
                    return True
            elif fnmatch.fnmatch(host, pattern):
                return True
            elif host == pattern:
                return True
            elif host in LOOPBACK_HOSTS and pattern in LOOPBACK_HOSTS:
                return True

    return False


def is_ip_allowed(ip_str: str, port: int, patterns: list[str]) -> bool:
    """Validate resolved IP.

    If the user explicitly allowlisted the IP or IP:port (or localhost:port for loopback)
    in their configuration, it is permitted. Otherwise, private, loopback, link-local
    (cloud metadata), and reserved IP ranges are blocked to prevent SSRF.
    """
    # Explicit bypass if directly listed in allowlist patterns
    for pattern in patterns:
        pattern = pattern.lower().strip()
        if pattern == ip_str or pattern == f"{ip_str}:{port}":
            return True
        if ip_str in LOOPBACK_HOSTS and (
            pattern in LOOPBACK_HOSTS
            or any(pattern == f"{lh}:{port}" for lh in LOOPBACK_HOSTS)
        ):
            return True

    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            return False
        return True
    except ValueError:
        return False


def report_deny(host: str, port: int, method: str, reason: str = "") -> None:
    """Print blocked outbound attempt directly to stderr for developer visibility."""
    reason_str = f" ({reason})" if reason else ""
    sys.stderr.write(f"agent-jail [proxy]: 🚫 Blocked {method} to {host}:{port}{reason_str}\n")
    sys.stderr.flush()


async def tunnel(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Bi-directional byte pump between client and upstream target."""
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    allowlist_path: str,
) -> None:
    """Handle incoming HTTP CONNECT or standard HTTP proxy requests."""
    try:
        line = await client_reader.readline()
        if not line:
            client_writer.close()
            return

        request_line = line.decode("utf-8", errors="replace").strip()
        parts = request_line.split()
        if len(parts) < 2:
            client_writer.close()
            return

        method, target = parts[0], parts[1]

        # Parse host and port
        if method.upper() == "CONNECT":
            if ":" in target:
                host, port_str = target.split(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
            else:
                host, port = target, 443
        else:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

        headers: list[bytes] = []
        while True:
            hdr = await client_reader.readline()
            if not hdr or hdr in (b"\r\n", b"\n"):
                break
            headers.append(hdr)

        patterns = parse_allowlist(allowlist_path)

        # 1. Check host & port against allowlist
        if not is_domain_allowed(host, port, patterns):
            report_deny(host, port, method, "Domain not in allowlist")
            err_body = f"403 Forbidden: '{host}:{port}' is not in the agent-jail allowlist.\n"
            resp = (
                f"HTTP/1.1 403 Forbidden\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(err_body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{err_body}"
            )
            client_writer.write(resp.encode("utf-8"))
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        # 2. DNS Resolution & SSRF Protection
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(
                host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        except Exception as e:
            err_body = f"502 Bad Gateway: Failed to resolve '{host}': {e}\n"
            resp = (
                f"HTTP/1.1 502 Bad Gateway\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(err_body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{err_body}"
            )
            client_writer.write(resp.encode("utf-8"))
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        # Filter resolved IPs against private/loopback/link-local ranges unless explicitly allowed
        valid_ip = None
        for item in addr_info:
            target_ip = item[4][0]
            if is_ip_allowed(target_ip, port, patterns):
                valid_ip = target_ip
                break
            else:
                report_deny(host, port, method, f"SSRF blocked: resolved to {target_ip}")

        if not valid_ip:
            err_body = f"403 Forbidden: '{host}' resolved to non-public/private IP address.\n"
            resp = (
                f"HTTP/1.1 403 Forbidden\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(err_body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{err_body}"
            )
            client_writer.write(resp.encode("utf-8"))
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        # 3. Connect to validated upstream IP
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(valid_ip, port), timeout=15.0
            )
        except Exception as e:
            err_body = f"502 Bad Gateway: Failed to connect to {host} ({valid_ip}:{port}): {e}\n"
            resp = (
                f"HTTP/1.1 502 Bad Gateway\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(err_body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{err_body}"
            )
            client_writer.write(resp.encode("utf-8"))
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        if method.upper() == "CONNECT":
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
            await asyncio.gather(
                tunnel(client_reader, remote_writer),
                tunnel(remote_reader, client_writer),
            )
        else:
            remote_writer.write(line)
            for h in headers:
                remote_writer.write(h)
            remote_writer.write(b"\r\n")
            await remote_writer.drain()
            await asyncio.gather(
                tunnel(client_reader, remote_writer),
                tunnel(remote_reader, client_writer),
            )
    except Exception:
        pass
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass


async def run_proxy(allowlist: str, port: int = 0, host: str = "127.0.0.1") -> None:
    """Run proxy server and emit PORT=<assigned_port> to stdout."""
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, allowlist),
        host=host,
        port=port,
    )

    assigned_port = server.sockets[0].getsockname()[1]
    sys.stdout.write(f"PORT={assigned_port}\n")
    sys.stdout.flush()

    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Jail Forward Proxy with SSRF Protection")
    parser.add_argument("--allowlist", required=True, help="Path to domain allowlist file")
    parser.add_argument("--port", type=int, default=0, help="Port to listen on (0 for dynamic)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind to")
    args = parser.parse_args()

    try:
        asyncio.run(run_proxy(allowlist=args.allowlist, port=args.port, host=args.host))
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
