"""
- Store threat intelligence
- Store final blocking decisions
- Allow agents to add new IOCs
"""


from typing import TypedDict, List


class IntelState(TypedDict):
    malicious_ips: List[str]
    malicious_domains: List[str]
    blocked_ips: List[str]
    blocked_domains: List[str]