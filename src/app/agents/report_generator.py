import os
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage
from langchain_core.tools import Tool
from langgraph.prebuilt import ToolNode
from dotenv import load_dotenv
from app.tools.generate_incident_report import generate_incident_report

load_dotenv()
model = os.getenv("GROQ_LLM_MODEL")

llm = ChatGroq(
    model=model,
    temperature=0.3
)

tools = [generate_incident_report]

llm_with_tools = llm.bind_tools(tools)

def report_agent(state):
  
    investigation_analysis = state["investigations"]

    response = llm_with_tools.invoke(
        [
            HumanMessage(
                content=f"""
                Use the tool to generate the SOC L2 incident report.

                Investigation Analysis:
                {investigation_analysis}
                """
            )
        ]
    )
    print(response)

    return state