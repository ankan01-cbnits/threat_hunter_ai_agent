import os
from langchain.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_groq import ChatGroq


@tool
def generate_incident_report(investigation_analysis: str) -> str:
    """
    L2 Incident Report Generator Tool

    Converts investigator agent analysis into a structured SOC incident report with severity scoring for L2 response prioritization.

    Input:
        investigation_analysis (str):
            Consolidated findings from analysis of multiple telemetry sources
            (DNS, authentication, system, network, and server logs).

    Output:
        str:
            Structured L2 SOC incident report including severity score.
    """
    model = os.getenv("GROQ_LLM_MODEL")
    llm = ChatGroq(
        model=model,
        temperature=0.5,
    )

    system_prompt = """
    You are a cybersecurity reporting assistant responsible for producing professional SOC incident reports for an L2 Security Operations team.

    Transform investigator analysis into a structured incident report.

    Include a Severity Score using this rubric:

    Severity Levels:
        - Critical: Active compromise, malware execution, data exfiltration, or lateral movement.
        - High: Confirmed malicious indicators or high probability of compromise.
        - Medium: Suspicious behavior requiring investigation but not confirmed malicious.
        - Low: Minor anomalies or policy violations with limited risk.
        - Informational: Benign events or baseline observations.

    Report Format:

    1. Incident Title
    2. Severity Score
    3. Executive Summary
    4. Investigation Overview
    5. Key Findings
    6. Affected Systems / Entities
    7. Evidence from Logs
        - DNS Logs
        - System Logs
        - Authentication Logs
        - Server/Application Logs
        - Network Logs (if available)
    8. Indicators of Compromise (IOCs)
    9. Risk Assessment
    10. Root Cause Hypothesis
    11. Recommended Actions for L2 Team
    12. Additional Notes

    Guidelines:
        - Base the severity only on the provided evidence.
        - Highlight suspicious indicators such as IPs, domains, hashes, or users.
        - Summarize log evidence clearly.
        - Do not fabricate missing data.
        - Maintain a professional SOC reporting tone.
    """

    try:
        response = llm.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(
                    content=f"""
                    Investigator Analysis Results:

                    {investigation_analysis}

                    Generate the L2 SOC incident report with severity scoring.
                    """
                ),
            ]
        )

        return response.content

    except Exception as e:
        return f"Report generation failed: {str(e)}"