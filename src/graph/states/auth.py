"""
- Store raw authentication events
- Track brute-force patterns
- Track successful logins
"""

from typing import TypedDict, List, Dict


class AuthEvent(TypedDict):
    timestamp: str
    event: str
    src_ip: str
    user: str
    service: str
    host: str

class SuccessfulLogins(TypedDict):
    src_ip: str
    user: str

class AuthState(TypedDict):
    events: List[AuthEvent]
    failed_attempts_by_ip: Dict[str, int]
    successful_logins: List[SuccessfulLogins]