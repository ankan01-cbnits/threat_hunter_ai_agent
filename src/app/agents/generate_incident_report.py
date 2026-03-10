import os
from langchain.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

from app.graph.states.__global import GlobalState
load_dotenv(override=True)

groq_base_url = os.getenv("GROQ_BASE_URL")
groq_api_key= os.getenv("GROQ_API_KEY")

def generate_incident_report(state:GlobalState):
    # """
    # L2 Incident Report Generator Tool

    # Converts investigator agent analysis into a structured SOC incident report with severity scoring for L2 response prioritization.

    # Input:
    #     investigation_analysis (str):
    #         Consolidated findings from analysis of multiple telemetry sources
    #         (DNS, authentication, system, network, and server logs).

    # Output:
    #     str:
    #         Structured L2 SOC incident report including severity score.
    # """
   
    llm = ChatOpenAI(
    model="llama-3.3-70b-versatile",
    base_url=groq_base_url,
    api_key=groq_api_key,
    temperature=0.4
    )

    investigations = state["investigations"]

    system_prompt = f"""
        You are a cybersecurity reporting assistant responsible for producing professional SOC incident reports for an L2 Security Operations team.

        Transform the investigation findings into a structured incident report.

        Investigation Data:
        {investigations}

        IMPORTANT:
        The output MUST be written in Markdown.

        Formatting Rules:

        - Each major section must be a level 3 heading using ###.
        - Bullet points must be used for summaries, findings, and recommendations.
        - Evidence logs should be grouped under the Evidence section.
        - Do not invent data that is not present.

        Required Report Structure:

        ### Incident Title

        ### Severity Score

        ### Executive Summary
        - Summarize the incident in bullet points.

        ### Investigation Overview
        - Bullet point explanation of investigation scope and analysis.

        ### Key Findings
        - Bullet points highlighting important discoveries.

        ### Affected Systems / Entities
        - List affected IPs, users, hosts, or domains.

        ### Indicators of Compromise (IOCs)
        - List suspicious IPs
        - Domains
        - File hashes
        - Users

        ### Risk Assessment
        - Bullet point explanation of impact and likelihood.

        ### Root Cause Hypothesis
        - Bullet point reasoning of how the activity occurred.

        ### Recommended Actions for L2 Team
        - Bullet point remediation steps.

        ### Additional Notes
        - Optional supporting observations.
        """

    try:
        response = llm.invoke(
            [
                SystemMessage(content=system_prompt),
            ]
        )
        
        print(response.content)
        state['report']=response.content

    except Exception as e:
        return f"Report generation failed: {str(e)}"
    
    return state

   