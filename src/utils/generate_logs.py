import random
from datetime import datetime, timedelta

start = datetime(2026,3,4,10,0,0)

internal_ips = [f"192.168.1.{i}" for i in range(10,40)]
external_ips = [
    "45.33.12.8",
    "185.22.45.9",
    "23.12.44.9",
    "91.200.12.44",
    "103.55.66.77"
]

domains = [
    "google.com",
    "github.com",
    "example.com",
    "c2.badserver.net",
    "data.exfil.com"
]

users = ["admin","root","john","alice","service"]

def ts(i):
    return (start + timedelta(seconds=i)).isoformat()

# AUTH LOGS
auth_logs=[]
for i in range(150):

    if i<25: # brute force
        ip="45.33.12.8"
        auth_logs.append(
            f"{ts(i)} AUTH_FAIL src_ip={ip} user=admin service=ssh host=server01"
        )
    else:
        ip=random.choice(internal_ips)
        user=random.choice(users)
        status=random.choice(["AUTH_SUCCESS","AUTH_FAIL"])

        auth_logs.append(
            f"{ts(i)} {status} src_ip={ip} user={user} service=ssh host=server01"
        )

# SERVER LOGS
server_logs=[]
for i in range(120):

    if i<20: # C2 beaconing
        ip="192.168.1.25"
        server_logs.append(
            f"{ts(i)} HTTP_REQ src_ip={ip} domain=c2.badserver.net uri=/update"
        )
    else:
        ip=random.choice(internal_ips)
        domain=random.choice(domains)

        server_logs.append(
            f"{ts(i)} HTTP_REQ src_ip={ip} domain={domain} uri=/index"
        )

# FIREWALL LOGS
firewall_logs=[]
for i in range(120):

    if i<20: # port scan
        ip="185.22.45.9"
        port=random.choice([22,80,443,21,23])

        firewall_logs.append(
            f"{ts(i)} NET_CONN src_ip={ip} dst_ip=192.168.1.10 dst_port={port} protocol=TCP"
        )
    else:
        src=random.choice(internal_ips)
        dst="8.8.8.8"

        firewall_logs.append(
            f"{ts(i)} FIREWALL_ALLOW src_ip={src} dst_ip={dst} dst_port=53 protocol=UDP"
        )

# DNS LOGS
dns_logs=[]
for i in range(110):

    if i<15: # DNS tunneling
        dns_logs.append(
            f"{ts(i)} DNS_QUERY src_ip=192.168.1.30 query=ajd92jd9a8d.data.exfil.com type=A"
        )
    else:
        ip=random.choice(internal_ips)
        domain=random.choice(domains)

        dns_logs.append(
            f"{ts(i)} DNS_QUERY src_ip={ip} query={domain} type=A"
        )

# WRITE FILES
def write(name,data):
    with open(f"data/{name}","w") as f:
        f.write("\n".join(data))

write("auth_logs.txt",auth_logs)
write("server_logs.txt",server_logs)
write("firewall_logs.txt",firewall_logs)
write("dns_logs.txt",dns_logs)

print("Logs generated successfully")