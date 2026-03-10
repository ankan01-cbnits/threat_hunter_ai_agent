from collections import defaultdict

from app.graph.states.__global import GlobalState


def correlation_agent(state:GlobalState):

    anomalies = state["anomalies"]

    incidents_by_ip = defaultdict(list)
    incidents_by_domain = defaultdict(list)

    for anomaly in anomalies:

        ip = anomaly.get("src_ip")
        domain = anomaly.get("domain")

        if ip:
            incidents_by_ip[ip].append(anomaly)

        if domain:
            incidents_by_domain[domain].append(anomaly)

    incidents = []

    # IP incidents
    for ip, events in incidents_by_ip.items():

        incidents.append({
            "type": "ip_incident",
            "entity": ip,
            "event_count": len(events),
            "anomalies": events
        })

    # Domain incidents
    for domain, events in incidents_by_domain.items():

        incidents.append({
            "type": "domain_incident",
            "entity": domain,
            "event_count": len(events),
            "anomalies": events
        })

    state["incidents"] = incidents

    print(f"Correlated {len(incidents)} incidents")

    return state