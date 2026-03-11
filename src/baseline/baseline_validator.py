# src/validators/baseline_validator.py

import time
import uuid
from prettyprinter import pprint
from app.graph.states.__global import GlobalState


# -------------------------
# STANDARD ANOMALY FORMAT
# -------------------------

def create_anomaly(
    anomaly_type,
    source,
    timestamp=None,
    src_ip=None,
    dst_ip=None,
    domain=None,
    severity="medium",
    details=None
):
    return {
        "id": str(uuid.uuid4()),
        "type": anomaly_type,
        "source": source,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "domain": domain,
        "severity": severity,
        "details": details or {}
    }


# -------------------------
# AUTH VALIDATION
# -------------------------

def validate_auth(state):

    anomalies = []

    baseline = state["baseline"]
    auth_state = state["auth"]

    events = auth_state.get("events", [])
    failures_by_ip = auth_state.get("failed_attempts_by_ip", {})

    for event in events:

        ip = event["src_ip"]
        failures = failures_by_ip.get(ip, 0)

        if failures > baseline["auth_failures_per_min"]:

            anomalies.append(
                create_anomaly(
                    anomaly_type="auth_bruteforce",
                    source="auth",
                    timestamp=event["timestamp"],
                    src_ip=ip,
                    severity="high",
                    details={
                        "failures": failures,
                        "user": event["user"],
                        "service": event["service"]
                    }
                )
            )

    return anomalies


# -------------------------
# DNS VALIDATION
# -------------------------

def validate_dns(state):

    anomalies = []

    baseline = state["baseline"]
    dns_state = state["dns"]

    for event in dns_state["events"]:

        domain = event["query"]

        if domain not in baseline["allowed_domains"]:

            anomalies.append(
                create_anomaly(
                    anomaly_type="dns_suspicious_domain",
                    source="dns",
                    timestamp=event["timestamp"],
                    src_ip=event["src_ip"],
                    domain=domain,
                    severity="medium",
                    details={
                        "record_type": event["record_type"]
                    }
                )
            )

    for ip, count in dns_state["queries_by_ip"].items():

        if count > baseline["dns_queries_per_ip_per_min"]:

            anomalies.append(
                create_anomaly(
                    anomaly_type="dns_excessive_queries",
                    source="dns",
                    src_ip=ip,
                    severity="medium",
                    details={
                        "queries": count
                    }
                )
            )

    return anomalies


# -------------------------
# FIREWALL VALIDATION
# -------------------------

def validate_firewall(state):

    anomalies = []

    baseline = state["baseline"]
    fw_state = state["firewall"]

    for event in fw_state["events"]:

        port = event["dst_port"]

        if port not in baseline["allowed_ports"]:

            anomalies.append(
                create_anomaly(
                    anomaly_type="suspicious_port",
                    source="firewall",
                    timestamp=event["timestamp"],
                    src_ip=event["src_ip"],
                    dst_ip=event["dst_ip"],
                    severity="medium",
                    details={
                        "dst_port": port,
                        "protocol": event["protocol"]
                    }
                )
            )

    for ip, count in fw_state["connections_by_src"].items():

        if count > baseline["connections_per_ip_per_min"]:

            anomalies.append(
                create_anomaly(
                    anomaly_type="possible_port_scan",
                    source="firewall",
                    src_ip=ip,
                    severity="high",
                    details={
                        "connections": count
                    }
                )
            )

    return anomalies


# -------------------------
# HTTP VALIDATION
# -------------------------

def validate_http(state):

    anomalies = []

    baseline = state["baseline"]
    server_state = state["server"]

    for event in server_state["events"]:

        domain = event["domain"]

        if domain not in baseline["allowed_domains"]:

            anomalies.append(
                create_anomaly(
                    anomaly_type="c2_domain",
                    source="http",
                    timestamp=event["timestamp"],
                    src_ip=event["src_ip"],
                    domain=domain,
                    severity="high",
                    details={
                        "uri": event["uri"]
                    }
                )
            )

    for ip, count in server_state["requests_by_ip"].items():

        if count > baseline["http_requests_per_ip_per_min"]:

            anomalies.append(
                create_anomaly(
                    anomaly_type="http_flood",
                    source="http",
                    src_ip=ip,
                    severity="high",
                    details={
                        "requests": count
                    }
                )
            )

    return anomalies


# -------------------------
# MASTER VALIDATOR
# -------------------------

def baseline_validator(state: GlobalState):

    print("Setting baselines...")
    time.sleep(1.5)
    anomalies = []

    anomalies += validate_auth(state)
    anomalies += validate_dns(state)
    anomalies += validate_firewall(state)
    anomalies += validate_http(state)

    state["anomalies"] = anomalies

    # pprint(anomalies)

    return state