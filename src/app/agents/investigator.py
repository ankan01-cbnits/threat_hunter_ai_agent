from app.graph.states.__global import GlobalState
from app.tools.dns_reputation import dns_reputation
from app.tools.ip_reputation import ip_reputation
from langchain_openai import ChatOpenAI
import os 
from dotenv import load_dotenv

load_dotenv(override=True)
groq_api_key = os.getenv("GROQ_API_KEY")
groq_base_url = os.getenv("GROQ_BASE_URL")

def investigator_node(state: GlobalState):

    llm = ChatOpenAI(
        model="llama-3.1-8b-instant",
        base_url=groq_base_url,
        api_key=groq_api_key,
        temperature=0.4
    )

    anomalies = state.get("anomalies", [])
    investigations = []

    for anomaly in anomalies:

        event = anomaly.get("event", {})

        src_ip = event.get("src_ip")
        domain = event.get("query_domain")

        intel_results = []

        # deterministic enrichment
        if src_ip:
            intel_results.append(
                ip_reputation.invoke({"ip": src_ip})
            )

        if domain:
            intel_results.append(
                dns_reputation.invoke({"domain": domain})
            )

        # LLM reasoning
        prompt = f"""
        You are a SOC investigation assistant.

        Anomaly:
        {anomaly}

        Threat intelligence results:
        {intel_results}

        Explain if this is malicious and what action SOC should take. Provide a proper summary for this.
        """

        analysis = llm.invoke(prompt)

        print("\n------ Investigation Summary ------")
        print(analysis.content)
        print("-----------------------------------\n")

        investigations.append({
            "anomaly_type": anomaly.get("type"),
            "event": event,
            "intel": intel_results,
            "analysis": analysis.content
        })

        print("\n\n\n------ Investigators JSON ------")
        print(investigations)
        print("-----------------------------------\n")      

    return investigations