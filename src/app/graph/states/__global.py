from typing import TypedDict

from app.graph.states.auth import AuthState
from app.graph.states.dns import DNSState
from app.graph.states.firewall import FirewallState
from app.graph.states.intel import IntelState
from app.graph.states.server import ServerState


class GlobalState(TypedDict):
    auth: AuthState
    dns: DNSState
    firewall: FirewallState
    server: ServerState
    intel: IntelState
    baseline: dict
    anomalies: list