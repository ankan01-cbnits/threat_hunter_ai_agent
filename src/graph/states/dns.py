"""
- Detect suspicious domains
- Track query frequency
- Detect DNS tunneling/exfiltration
"""


from typing import TypedDict, List, Dict


class DNSEvent(TypedDict):
    timestamp: str
    src_ip: str
    query: str
    record_type: str


class DNSState(TypedDict):
    events: List[DNSEvent]
    queries_by_domain: Dict[str, int]
    queries_by_ip: Dict[str, int]
    suspicious_domains: List[str]