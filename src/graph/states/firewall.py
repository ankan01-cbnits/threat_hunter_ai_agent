"""
- Detect port scanning
- Track inbound connections
- Identify suspicious source IPs
"""


from typing import TypedDict, List, Dict


class FirewallEvent(TypedDict):
    timestamp: str
    event: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str


class FirewallState(TypedDict):
    events: List[FirewallEvent]
    connections_by_src: Dict[str, int]
    ports_scanned: Dict[str, List[int]]