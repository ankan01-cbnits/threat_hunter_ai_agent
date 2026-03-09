import random
import os
from datetime import datetime, timedelta

start = datetime(2026, 3, 4, 9, 0, 0)

ips = [f"192.168.1.{i}" for i in range(10,40)]
users = ["john","alice","admin","service"]
domains = ["google.com","github.com","example.com"]
ports = [53,80,443]

BASE_DIR = os.path.dirname(__file__)
log_path = os.path.join(BASE_DIR, "normallogs.txt")

with open(log_path, "w") as f:

    for i in range(3600):  # 1 hour

        t = start + timedelta(seconds=i)

        log_type = random.choice(["auth","dns","firewall","http"])

        if log_type == "auth":

            event = random.choices(
                ["AUTH_SUCCESS","AUTH_FAIL"],
                weights=[0.9,0.1]
            )[0]

            line = f"{t} {event} src_ip={random.choice(ips)} user={random.choice(users)} service=ssh host=server01"


        elif log_type == "dns":

            line = f"{t} DNS_QUERY src_ip={random.choice(ips)} query={random.choice(domains)} type=A"


        elif log_type == "firewall":

            line = f"{t} FIREWALL_ALLOW src_ip={random.choice(ips)} dst_ip=8.8.8.8 dst_port={random.choice(ports)} protocol=TCP"


        else:

            line = f"{t} HTTP_REQ src_ip={random.choice(ips)} domain={random.choice(domains)} uri=/index"


        f.write(line + "\n")

print("normallogs.txt generated at:", log_path)