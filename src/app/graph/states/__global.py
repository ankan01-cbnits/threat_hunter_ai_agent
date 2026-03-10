from typing import TypedDict,List

from .auth import AuthState
from .dns import DNSState
from .firewall import FirewallState
from .intel import IntelState
from .server import ServerState


class GlobalState(TypedDict):
    auth: AuthState
    dns: DNSState
    firewall: FirewallState
    server: ServerState
    intel: IntelState
    baseline: dict
    anomalies: list
    incidents: List[dict]         
    investigations: List[dict]   