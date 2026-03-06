"""
- Track HTTP requests
- Detect command-and-control callbacks
- Detect suspicious domains
"""


from typing import TypedDict, List, Dict


class HTTPEvent(TypedDict):
    timestamp: str
    src_ip: str
    domain: str
    uri: str


class ServerState(TypedDict):
    events: List[HTTPEvent]
    requests_by_domain: Dict[str, int]
    requests_by_ip: Dict[str, int]
    suspicious_domains: List[str]