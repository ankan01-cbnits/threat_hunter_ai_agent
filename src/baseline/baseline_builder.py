from collections import defaultdict
from datetime import datetime
import statistics
import json



def parse_fields(parts):

    data = {}

    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            data[k] = v

    return data


def minute_bucket(date, time):

    t = datetime.strptime(date + " " + time, "%Y-%m-%d %H:%M:%S")

    return t.strftime("%Y-%m-%d %H:%M")


def threshold(values, default):

    if not values:
        return default

    mean = statistics.mean(values)

    if len(values) > 1:
        std = statistics.stdev(values)
    else:
        std = 0

    return int(mean + (2 * std))


def build_baseline(log_file):

    auth_fail_per_min = defaultdict(int)
    dns_per_ip_per_min = defaultdict(int)
    http_per_ip_per_min = defaultdict(int)
    conn_per_ip_per_min = defaultdict(int)

    domain_counts = defaultdict(int)
    port_counts = defaultdict(int)

    with open(log_file) as f:

        for line in f:

            parts = line.strip().split()

            if len(parts) < 3:
                continue

            date = parts[0]
            time = parts[1]
            event = parts[2]

            fields = parse_fields(parts)

            bucket = minute_bucket(date, time)

            # AUTH
            if event == "AUTH_FAIL":

                auth_fail_per_min[bucket] += 1

            # DNS
            elif event == "DNS_QUERY":

                ip = fields.get("src_ip")
                domain = fields.get("query")

                if ip:
                    dns_per_ip_per_min[(bucket, ip)] += 1

                if domain:
                    domain_counts[domain] += 1

            # FIREWALL
            elif event == "FIREWALL_ALLOW":

                ip = fields.get("src_ip")
                port = fields.get("dst_port")

                if ip:
                    conn_per_ip_per_min[(bucket, ip)] += 1

                if port:
                    port_counts[int(port)] += 1

            # HTTP
            elif event == "HTTP_REQ":

                ip = fields.get("src_ip")
                domain = fields.get("domain")

                if ip:
                    http_per_ip_per_min[(bucket, ip)] += 1

                if domain:
                    domain_counts[domain] += 1

    baseline = {

        "auth_failures_per_min":
            threshold(list(auth_fail_per_min.values()), 2),

        "dns_queries_per_ip_per_min":
            threshold(list(dns_per_ip_per_min.values()), 10),

        "http_requests_per_ip_per_min":
            threshold(list(http_per_ip_per_min.values()), 10),

        "connections_per_ip_per_min":
            threshold(list(conn_per_ip_per_min.values()), 15),

        "allowed_domains":
            [d for d, c in domain_counts.items() if c > 5],

        "allowed_ports":
            [p for p, c in port_counts.items() if c > 5]
    }

    return baseline


if __name__ == "__main__":

    baseline = build_baseline("src\\baseline\\normallogs.txt")
    # state["baseline"] = baseline

    print(json.dumps(baseline, indent=2))