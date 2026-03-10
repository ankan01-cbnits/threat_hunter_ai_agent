from langchain.tools import tool
from datetime import datetime, timezone
# temporary threat intel source
KNOWN_MALICIOUS_IPS = {
    "45.33.12.8": {"confidence": 95, "source": "abuseipdb"},
    "103.21.244.1": {"confidence": 90, "source": "otx"},
}


@tool
def ip_reputation(ip: str) -> dict:
    """
    Check reputation of an IP address.
    Returns structured threat intelligence result.
    Do not use web access.
    """

    if ip in KNOWN_MALICIOUS_IPS:

        intel = KNOWN_MALICIOUS_IPS[ip]  #change this to take ip from a source like: VirusTotal, GreyNoise, AlienVault OTX

        return {
            "tool": "ip_reputation",
            "ip": ip,
            "reputation": "malicious",
            "confidence": intel["confidence"],
            "source": intel["source"],
            "recommended_action": "block",
            "timestamp": datetime.now(timezone.utc)
        }

    return {
        "tool": "ip_reputation",
        "ip": ip,
        "reputation": "unknown",
        "confidence": 0,
        "source": "none",
        "recommended_action": "investigate",
        "timestamp": datetime.now(timezone.utc)
    }