from app.graph.states.__global import GlobalState
from app.tools.dns_reputation import dns_reputation
from app.tools.ip_reputation import ip_reputation

from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

import os

load_dotenv(override=True)

groq_api_key = os.getenv("GROQ_API_KEY")
groq_base_url = os.getenv("GROQ_BASE_URL")


llm = ChatOpenAI(
    model="llama-3.1-8b-instant",
    base_url=groq_base_url,
    api_key=groq_api_key,
    temperature=0.4
)

tools = [ip_reputation, dns_reputation]


prompt = ChatPromptTemplate.from_messages(
            [
            (
            "system",
            """
            You are an AI SOC investigation assistant.

            You investigate security incidents and may use tools when needed.

            Available tools:
            - ip_reputation
            - dns_reputation

            Rules:
            • Use ip_reputation when the incident involves an IP.
            • Use dns_reputation when the incident involves a domain.
            • Investigate anomalies and determine if the activity is malicious.
            • Always use ip reputation and domain reputation tool and do not use any other tools 
            • Do not use web access
            

            Return a clear SOC investigation summary with recommended action.
            """
            ),
            ("human", "{input}"),
            ("{agent_scratchpad}")
            ]
            )


agent = create_agent(
    model=llm,
    tools=tools,
    system_prompt="You are a SOC investigation assistant."
)


def investigator_agent(state: GlobalState):

    incidents = state.get("incidents", [])
    investigations = []

    for incident in incidents:

        query = f"""
                Investigate this incident.

                Incident type: {incident["type"]}
                Entity: {incident["entity"]}
                Event count: {incident["event_count"]}

                Anomalies:
                {incident["anomalies"]}
                """

        result = agent.invoke(
            {"input": query}
        )

        analysis = result["messages"][-1].content

        print("\n------ Investigation Summary ------")
        print(analysis)
        print("-----------------------------------\n")

        investigations.append({
            "incident_type": incident["type"],
            "entity": incident["entity"],
            "analysis": analysis
        })

    return investigations