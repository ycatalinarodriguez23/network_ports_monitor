#!/usr/bin/env python3
"""
network_ports_monitor.py

Lists the network ports currently in use on this machine and shows
which process (PID and name) owns each connection.

Requires:
    pip install psutil

Usage:
    python3 network_ports_monitor.py
    python3 network_ports_monitor.py --state LISTEN
"""

import argparse
import psutil


def get_process_name(pid: int) -> str:
    """Return the process name for a given PID, or 'Unknown' if it can't be read.

    Some processes (e.g. owned by another user, or system processes) may not
    be accessible, so we handle those exceptions gracefully.
    """
    if pid is None:
        return "N/A (no PID / kernel)"
    try:
        process = psutil.Process(pid)
        return process.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown/Access Denied"


def list_network_connections(state_filter: str = None):
    """Print every active network connection along with the owning process.

    Args:
        state_filter: Optional connection state to filter by (e.g. "LISTEN",
            "ESTABLISHED"). If None, all states are shown.
    """
    connections = psutil.net_connections(kind="inet")

    header = f"{'Proto':<6} {'Local Address':<25} {'Remote Address':<25} {'State':<12} {'PID':<8} {'Process Name'}"
    print(header)
    print("-" * len(header))

    for conn in connections:
        # Filter by connection state if requested
        if state_filter and conn.status != state_filter:
            continue

        proto = "TCP" if conn.type.name == "SOCK_STREAM" else "UDP"

        local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
        state = conn.status if conn.status else "N/A"
        pid = conn.pid
        process_name = get_process_name(pid)

        print(f"{proto:<6} {local_address:<25} {remote_address:<25} {state:<12} {str(pid):<8} {process_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Show which ports are currently in use and by which process."
    )
    parser.add_argument(
        "--state",
        type=str,
        default=None,
        help="Filter connections by state (e.g. LISTEN, ESTABLISHED, TIME_WAIT).",
    )
    args = parser.parse_args()

    print("Note: run this script with administrator/root privileges to see")
    print("process information for connections owned by other users.\n")

    list_network_connections(state_filter=args.state)


if __name__ == "__main__":
    main()
