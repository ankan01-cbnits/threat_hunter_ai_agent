import re
from pathlib import Path
from typing import List, Dict

from app.graph.states.auth import AuthEvent, SuccessfulLogins, AuthState
from app.graph.states.dns import DNSEvent, DNSState
from app.graph.states.firewall import FirewallEvent, FirewallState
from app.graph.states.server import HTTPEvent, ServerState


LOG_DIR = Path("src/data/logs")


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
def parse_auth_logs() -> AuthState:

    events: List[AuthEvent] = []
    failed_attempts_by_ip: Dict[str, int] = {}
    successful_logins: List[SuccessfulLogins] = []

    path = LOG_DIR / "auth_logs.txt"

    if not path.exists():
        return AuthState(
                events=[],
                failed_attempts_by_ip={},
                successful_logins=[]
            )

    content = path.read_text()
    
    # Fix rare case where two log lines get concatenated
    content = re.sub(r"(server\d+)(\d{4}-\d{2}-\d{2}T)", r"\1\n\2", content)

    for line in content.splitlines():

        line = line.strip()
        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]
        event = parts[1]

        data = parse_kv_pairs(parts[2:])

        auth_event: AuthEvent = AuthEvent(
            timestamp=timestamp,
            event=event,
            src_ip=data.get("src_ip", ""),
            user=data.get("user", ""),
            service=data.get("service", ""),
            host=data.get("host", "")
        )

        events.append(auth_event)

        if event == "AUTH_FAIL":
            ip = auth_event["src_ip"]
            failed_attempts_by_ip[ip] = failed_attempts_by_ip.get(ip, 0) + 1

        elif event == "AUTH_SUCCESS":
            successful_logins.append(
                SuccessfulLogins(
                    src_ip=auth_event["src_ip"],
                    user=auth_event["user"]
                )
            )

    return AuthState(
            events=events,
            failed_attempts_by_ip=failed_attempts_by_ip,
            successful_logins=successful_logins
        )


# -------------------------
# DNS LOGS
# -------------------------
def parse_dns_logs() -> DNSState:

    events: List[DNSEvent] = []
    queries_by_domain: Dict[str, int] = {}
    queries_by_ip: Dict[str, int] = {}

    path = LOG_DIR / "dns_logs.txt"

    if not path.exists():
        return DNSState(
                events=[],
                queries_by_domain={},
                queries_by_ip={},
                suspicious_domains=[]
            )

    for line in path.read_text().splitlines():

        line = line.strip()
        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]

        data = parse_kv_pairs(parts[2:])

        dns_event: DNSEvent = DNSEvent(
            timestamp=timestamp,
            src_ip=data.get("src_ip", ""),
            query=data.get("query", ""),
            record_type=data.get("type", "")
        )

        events.append(dns_event)

        domain = dns_event["query"]
        ip = dns_event["src_ip"]

        # Track domain frequency
        queries_by_domain[domain] = queries_by_domain.get(domain, 0) + 1

        # Track queries per IP
        queries_by_ip[ip] = queries_by_ip.get(ip, 0) + 1

    return DNSState(
            events=events,
            queries_by_domain=queries_by_domain,
            queries_by_ip=queries_by_ip,
            suspicious_domains=[]
        )


# -------------------------
# FIREWALL LOGS
# -------------------------
def parse_firewall_logs() -> FirewallState:

    events: List[FirewallEvent] = []
    connections_by_src: Dict[str, int] = {}
    ports_scanned: Dict[str, List[int]] = {}

    path = LOG_DIR / "firewall_logs.txt"

    if not path.exists():
        return FirewallState(
                events=[],
                connections_by_src={},
                ports_scanned={}
            )

    for line in path.read_text().splitlines():

        line = line.strip()
        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]
        event = parts[1]

        data = parse_kv_pairs(parts[2:])

        src_ip = data.get("src_ip", "")
        dst_port = int(data.get("dst_port", 0))

        firewall_event: FirewallEvent = FirewallEvent(
            timestamp=timestamp,
            event=event,
            src_ip=src_ip,
            dst_ip=data.get("dst_ip", ""),
            dst_port=dst_port,
            protocol=data.get("protocol", "")
        )

        events.append(firewall_event)

        # Count connections per source IP
        connections_by_src[src_ip] = connections_by_src.get(src_ip, 0) + 1

        # Track ports contacted by each source IP
        if src_ip not in ports_scanned:
            ports_scanned[src_ip] = []

        if dst_port not in ports_scanned[src_ip]:
            ports_scanned[src_ip].append(dst_port)

    return FirewallState(
            events=events,
            connections_by_src=connections_by_src,
            ports_scanned=ports_scanned
        )


# # -------------------------
# # SERVER LOGS
# # -------------------------
def parse_server_logs() -> ServerState:

    events: List[HTTPEvent] = []
    requests_by_domain: Dict[str, int] = {}
    requests_by_ip: Dict[str, int] = {}

    path = LOG_DIR / "server_logs.txt"

    if not path.exists():
        return ServerState(
                events=[],
                requests_by_domain={},
                requests_by_ip={},
                suspicious_domains=[]
            )

    for line in path.read_text().splitlines():

        line = line.strip()
        if not line:
            continue

        parts = line.split()

        timestamp = parts[0]

        data = parse_kv_pairs(parts[2:])

        src_ip = data.get("src_ip", "")
        domain = data.get("domain", "")

        http_event: HTTPEvent = HTTPEvent(
            timestamp=timestamp,
            src_ip=src_ip,
            domain=domain,
            uri=data.get("uri", "")
        )

        events.append(http_event)

        # Count requests per domain
        requests_by_domain[domain] = requests_by_domain.get(domain, 0) + 1

        # Count requests per IP
        requests_by_ip[src_ip] = requests_by_ip.get(src_ip, 0) + 1

    return ServerState(
            events=events,
            requests_by_domain=requests_by_domain,
            requests_by_ip=requests_by_ip,
            suspicious_domains=[]
        )


# # -------------------------
# # MASTER PARSER
# # -------------------------
def parse_all_logs():

    return {
        "auth": parse_auth_logs(),
        "dns": parse_dns_logs(),
        "firewall": parse_firewall_logs(),
        "server": parse_server_logs()
    }
