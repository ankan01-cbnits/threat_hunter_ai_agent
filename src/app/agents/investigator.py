from app.graph.states.__global import GlobalState
from app.tools.dns_reputation import dns_reputation
from app.tools.ip_reputation import ip_reputation

from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from dotenv import load_dotenv

import os

load_dotenv(override=True)

groq_api_key = os.getenv("GROQ_API_KEY")
groq_base_url = os.getenv("GROQ_BASE_URL")


# -------------------------
# LLM
# -------------------------

llm = ChatOpenAI(
    model="llama-3.3-70b-versatile",
    base_url=groq_base_url,
    api_key=groq_api_key,
    temperature=0.4
)

tools = [ip_reputation, dns_reputation]


# -------------------------
# AGENT
# -------------------------

agent = create_agent(
    model=llm,
    tools=tools,
    system_prompt="""
You are an AI SOC investigation assistant.

You analyze multiple correlated incidents together.

You may use:
- ip_reputation
- dns_reputation

Rules:
• Use tools only when needed
• Analyze patterns across incidents
• Identify suspicious entities
• Produce a SOC investigation report
"""
)


# -------------------------
# INCIDENT COMPRESSION
# -------------------------

def compress_incident(incident):

    return {
        "type": incident.get("type"),
        "entity": incident.get("entity"),
        "event_count": incident.get("event_count"),
        "severity": incident.get("severity")
    }


# -------------------------
# INVESTIGATOR NODE
# -------------------------

def investigator_agent(state: GlobalState):
    llm_calls = 0
    incidents = state.get("incidents", [])

    compressed_incidents = [
        compress_incident(i) for i in incidents
    ]

    query = f"""
        You are investigating correlated security incidents.

        Compressed Incident Data
        ------------------------
        {compressed_incidents}

        Tasks
        -----

        1. Identify suspicious IPs and domains.
        2. Determine attack patterns across incidents.
        3. Use reputation tools when needed.
        4. Determine overall risk level.
        5. Provide recommended SOC response.

        Report Format
        -------------

        Incident Overview
        Suspicious Entities
        Attack Behaviour
        Risk Level
        Recommended Actions
        """
    llm_calls = llm_calls+1
    result = agent.invoke(
        {
            "messages": [
                ("user", query)
            ]
        }
    )

    analysis = result["messages"][-1].content

    print("\n------ SOC Investigation Report ------")
    print(analysis)
    print("--------------------------------------\n")

    state["investigations"] = analysis
    print("Total LLM calls:", llm_calls)
    return state
