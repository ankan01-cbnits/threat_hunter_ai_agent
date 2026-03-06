import re
from pathlib import Path
from typing import List

from graph.states.auth import AuthEvent
from graph.states.dns import DNSEvent
from graph.states.firewall import FirewallEvent
from graph.states.server import HTTPEvent


LOG_DIR = Path("data/logs")


# -------------------------
# Helper
# -------------------------

def parse_kv_pairs(parts: List[str]) -> dict:
    """
    Convert key=value tokens into dict
    """
    data = {}
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            data[k] = v
    return data


# -------------------------
# AUTH LOGS
# -------------------------

def parse_auth_logs() -> List[AuthEvent]:

    events: List[AuthEvent] = []

    path = LOG_DIR / "auth_logs.txt"

    if not path.exists():
        return events

    content = path.read_text()

    # Fix possible concatenated timestamps
    content = re.sub(r"(server\d+)(\d{4}-\d{2}-\d{2}T)", r"\1\n\2", content)

    for line in content.splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]
        event = parts[1]

        data = parse_kv_pairs(parts[2:])

        events.append(
            AuthEvent(
                timestamp=timestamp,
                event=event,
                src_ip=data.get("src_ip", ""),
                user=data.get("user", ""),
                service=data.get("service", ""),
                host=data.get("host", "")
            )
        )

    return events


# -------------------------
# DNS LOGS
# -------------------------

def parse_dns_logs() -> List[DNSEvent]:

    events: List[DNSEvent] = []

    path = LOG_DIR / "dns_logs.txt"

    if not path.exists():
        return events

    for line in path.read_text().splitlines():

        line = line.strip()
        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]

        data = parse_kv_pairs(parts[2:])

        events.append(
            DNSEvent(
                timestamp=timestamp,
                src_ip=data.get("src_ip", ""),
                query=data.get("query", ""),
                record_type=data.get("type", "")
            )
        )

    return events


# -------------------------
# FIREWALL LOGS
# -------------------------

def parse_firewall_logs() -> List[FirewallEvent]:

    events: List[FirewallEvent] = []

    path = LOG_DIR / "firewall_logs.txt"

    if not path.exists():
        return events

    for line in path.read_text().splitlines():

        line = line.strip()
        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]
        event = parts[1]

        data = parse_kv_pairs(parts[2:])

        events.append(
            FirewallEvent(
                timestamp=timestamp,
                event=event,
                src_ip=data.get("src_ip", ""),
                dst_ip=data.get("dst_ip", ""),
                dst_port=int(data.get("dst_port", 0)),
                protocol=data.get("protocol", "")
            )
        )

    return events


# -------------------------
# SERVER LOGS
# -------------------------

def parse_server_logs() -> List[HTTPEvent]:

    events: List[HTTPEvent] = []

    path = LOG_DIR / "server_logs.txt"

    if not path.exists():
        return events

    for line in path.read_text().splitlines():

        line = line.strip()
        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]

        data = parse_kv_pairs(parts[2:])

        events.append(
            HTTPEvent(
                timestamp=timestamp,
                src_ip=data.get("src_ip", ""),
                domain=data.get("domain", ""),
                uri=data.get("uri", "")
            )
        )

    return events


# -------------------------
# MASTER PARSER
# -------------------------

def parse_all_logs():

    return {
        "auth": parse_auth_logs(),
        "dns": parse_dns_logs(),
        "firewall": parse_firewall_logs(),
        "server": parse_server_logs()
    }
