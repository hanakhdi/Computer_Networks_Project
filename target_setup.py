from __future__ import annotations

import argparse
import ipaddress
import os
import subprocess
import sys


RULE_COMMENT = "vpn-phase1-target-block"


def require_linux_root() -> None:
    if os.name != "posix":
        raise RuntimeError("this script supports Linux only")
    if os.geteuid() != 0:
        raise RuntimeError("run this script with sudo")


def rule_arguments(client_ip: str, interface: str) -> list[str]:
    address = str(ipaddress.IPv4Address(client_ip))
    return [
        "-i",
        interface,
        "-s",
        address,
        "-m",
        "comment",
        "--comment",
        RULE_COMMENT,
        "-j",
        "DROP",
    ]


def run_iptables(action: str, rule: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["iptables", "-w", action, "INPUT", *rule],
            check=False,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("iptables is not installed") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Block direct traffic from the VPN client's real IP"
    )
    parser.add_argument("--blocked-client-ip", required=True)
    parser.add_argument("--interface", required=True)
    args = parser.parse_args()

    try:
        require_linux_root()
        rule = rule_arguments(args.blocked_client_ip, args.interface)
        check = run_iptables("-C", rule)
        if check.returncode == 0:
            print("[TARGET] matching firewall rule already exists")
            return
        if check.returncode != 1:
            detail = check.stderr.strip() or "could not inspect iptables rules"
            raise RuntimeError(detail)
        added = run_iptables("-A", rule)
        if added.returncode != 0:
            detail = added.stderr.strip() or "unknown iptables error"
            raise RuntimeError(f"could not add firewall rule: {detail}")
        print(
            f"[TARGET] direct traffic from {args.blocked_client_ip} "
            f"on {args.interface} is now blocked"
        )
    except Exception as exc:
        print(f"[TARGET] error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
