from langchain.tools import tool
from datetime import datetime, timezone


# Temporary threat intelligence dataset
KNOWN_MALICIOUS_DOMAINS = {
    "malicious-login.com": {
        "confidence": 92,
        "source": "alienvault_otx",
        "category": "phishing"
    },
    "crypto-miner.net": {
        "confidence": 88,
        "source": "virustotal",
        "category": "cryptominer"
    }
}


@tool
def dns_reputation(domain: str) -> dict:
    """
    Simulated DNS reputation lookup.

    In production this would query:
    - VirusTotal
    - Cisco Umbrella
    - AlienVault OTX
    - Passive DNS sources
    Note: Do not use web access.
    """

    intel = KNOWN_MALICIOUS_DOMAINS.get(domain)

    if intel:

        return {
            "tool": "dns_reputation",
            "domain": domain,
            "reputation": "malicious",
            "confidence": intel["confidence"],
            "category": intel["category"],
            "source": intel["source"],
            "recommended_action": "block_domain",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    return {
        "tool": "dns_reputation",
        "domain": domain,
        "reputation": "unknown",
        "confidence": 0,
        "category": "none",
        "source": "local_db",
        "recommended_action": "investigate",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }