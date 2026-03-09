from langchain.tools import tool
from datetime import datetime

fake_logs = [
        {
            "timestamp": "2026-03-04T10:00:13",
            "src_ip": "45.33.12.8",
            "user": "admin",
            "host": "server01",
            "event": "AUTH_FAIL"
        },
        {
            "timestamp": "2026-03-04T10:02:41",
            "src_ip": "45.33.12.8",
            "user": "admin",
            "host": "server01",
            "event": "AUTH_FAIL"
        },
        {
            "timestamp": "2026-03-04T10:05:02",
            "src_ip": "45.33.12.8",
            "user": "admin",
            "host": "server01",
            "event": "AUTH_SUCCESS"
        }
    ]

@tool
def query_tool(query: str) -> dict:
    """
    Execute a security investigation query against log data.
    Useful for retrieving historical authentication events,
    IP activity, or host behaviour patterns.
    """

    # ---- static simulation (replace later with real query engine) ----
    return {
        "tool": "query_tool",
        "query": query,
        "results": fake_logs,
        "result_count": len(fake_logs),
        "timestamp": datetime.now(datetime.timezone.utc)
    }