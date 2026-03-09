# src/validators/baseline_validator.py


# -------------------------
# AUTH VALIDATION
# -------------------------
def validate_auth(state):

    anomalies = []

    baseline = state["baseline"]

    for ip, failures in state["auth"]["failed_attempts_by_ip"].items():

        if failures > baseline["auth_failures_per_min"]:

            anomalies.append({
                "type": "auth_bruteforce",
                "src_ip": ip,
                "failures": failures
            })

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

            anomalies.append({
                "type": "dns_suspicious_domain",
                "event": event
            })

    for ip, count in dns_state["queries_by_ip"].items():

        if count > baseline["dns_queries_per_ip_per_min"]:

            anomalies.append({
                "type": "dns_excessive_queries",
                "src_ip": ip,
                "queries": count
            })

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

            anomalies.append({
                "type": "suspicious_port",
                "event": event
            })

    for ip, count in fw_state["connections_by_src"].items():

        if count > baseline["connections_per_ip_per_min"]:

            anomalies.append({
                "type": "possible_port_scan",
                "src_ip": ip,
                "connections": count
            })

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

            anomalies.append({
                "type": "c2_domain",
                "event": event
            })

    for ip, count in server_state["requests_by_ip"].items():

        if count > baseline["http_requests_per_ip_per_min"]:

            anomalies.append({
                "type": "http_flood",
                "src_ip": ip,
                "requests": count
            })

    return anomalies


# -------------------------
# MASTER VALIDATOR
# -------------------------
def baseline_validator(state):

    anomalies = []

    anomalies += validate_auth(state)
    anomalies += validate_dns(state)
    anomalies += validate_firewall(state)
    anomalies += validate_http(state)

    state["anomalies"] = anomalies

    return state