from app.graph.graph_builder import graph_compiler

def main():
    print("--------------------------------STARTING--------------------------------")
    runnable_graph = graph_compiler()
    runnable_graph.invoke({ 
    "baseline":{
        "auth_failures_per_min": 4,
        "dns_queries_per_ip_per_min": 2,
        "http_requests_per_ip_per_min": 2,
        "connections_per_ip_per_min": 2,
        "allowed_domains": [
            "google.com",
            "github.com",
            "example.com"
        ],
        "allowed_ports": [
            80,
            53,
            443
        ]
    }
},

config={
    "configurable": {
        "thread_id": "soc-session-1"
    }
})


if __name__ == "__main__":
    main()
    