"""A narrowly scoped TCP port status checker."""

import argparse
import ipaddress
import socket


def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True when a TCP connection succeeds; never scans a port range."""
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Hostnames are allowed, but reject whitespace/control characters.
        if not host or any(ord(c) < 32 or c.isspace() for c in host):
            raise ValueError("host must be an IP address or a valid hostname")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Check one TCP port on an authorized host.")
    parser.add_argument("port", type=int)
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()
    try:
        state = "OPEN" if check_port(args.host, args.port, args.timeout) else "CLOSED or FILTERED"
        print(f"{args.host}:{args.port} -> {state}")
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
