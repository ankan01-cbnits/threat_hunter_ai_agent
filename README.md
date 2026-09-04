# 🛡️ Threat Hunter AI Agent

**AI-powered multi-agent cybersecurity workflow built with LangGraph** — automatically analyzes security logs, detects anomalies, correlates suspicious activity, investigates potential threats, generates structured SOC reports, and sends investigation results through email.

---

## ✨ What It Does

The Threat Hunter AI Agent processes multiple types of security logs and performs automated threat investigation:

1. **Parses** authentication, DNS, firewall, and server logs
2. **Detects** anomalous behaviour using configurable security baselines
3. **Correlates** anomalies by suspicious IP addresses and domains
4. **Investigates** correlated incidents using an LLM-powered SOC investigation agent
5. **Enriches** suspicious IPs and domains using reputation tools
6. **Generates** a structured SOC incident report with severity and recommended actions
7. **Sends** the generated report through email

The complete workflow is orchestrated using **LangGraph**, with shared state being passed between each stage.

---

## 🛠️ Tech Stack

| Component              | Technology                                 |
| ---------------------- | ------------------------------------------ |
| Language               | Python 3.12+                               |
| Agent Framework        | LangChain                                  |
| Workflow Orchestration | LangGraph                                  |
| LLM                    | Llama 3.3 70B                              |
| LLM Provider           | Groq                                       |
| LLM Integration        | `langchain-openai` / OpenAI-compatible API |
| Workflow State         | LangGraph `GlobalState`                    |
| Checkpointing          | SQLite                                     |
| Data Validation        | Pydantic                                   |
| Configuration          | Python Dotenv                              |
| Reporting              | Markdown                                   |
| Notifications          | SMTP / Gmail                               |
| Package Management     | uv / pip                                   |

The project requires Python 3.12 or newer and includes LangGraph, LangChain, Groq/OpenAI integrations, SQLite checkpointing, Pydantic, and Python Dotenv dependencies.

---

## 🚀 Quick Start

### Step 1: Clone the Repository

```bash
git clone https://github.com/ankan01-cbnits/threat_hunter_ai_agent.git
cd threat_hunter_ai_agent
```

### Step 2: Create the Environment

Using `uv`:

```bash
uv sync
```

Or using pip:

```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables

Create a `.env` file:

```bash
GROQ_API_KEY="your-groq-api-key"
GROQ_LLM_MODEL="llama-3.3-70b-versatile"

EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-password"
EMAIL_TO="recipient@example.com"
```

The repository's environment template currently defines `GROQ_API_KEY` and `GROQ_LLM_MODEL`.

The email agent additionally reads `EMAIL_USER`, `EMAIL_PASS`, and `EMAIL_TO` and sends the generated report through Gmail SMTP on port 587.

### Step 4: Run the Agent

```bash
python -m src.app.main
```

If the package is being executed with the `src` directory on the Python path:

```bash
PYTHONPATH=src python -m app.main
```

---

## 📁 Project Structure

```bash
threat_hunter_ai_agent/
├── src/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── correlation_agent.py
│   │   │   ├── investigator.py
│   │   │   ├── generate_incident_report.py
│   │   │   └── mailer.py
│   │   ├── graph/
│   │   │   ├── graph_builder.py
│   │   │   └── states/
│   │   ├── memory/
│   │   │   └── states.db
│   │   ├── tools/
│   │   │   ├── parse_logs.py
│   │   │   ├── ip_reputation.py
│   │   │   └── dns_reputation.py
│   │   └── main.py
│   ├── baseline/
│   │   ├── baseline_validator.py
│   │   ├── baseline_builder.py
│   │   └── normallogs.txt
│   ├── data/
│   │   └── logs/
│   │       ├── auth_logs.txt
│   │       ├── dns_logs.txt
│   │       ├── firewall_logs.txt
│   │       └── server_logs.txt
│   └── ingestion/
│       └── log_parser.py
├── .env_example
├── pyproject.toml
├── requirements.txt
└── uv.lock
```

The repository separates agent logic, graph orchestration, state/memory, tools, baseline validation, and sample security logs.

---

## 🏗️ How It Works

The workflow is implemented as a LangGraph `StateGraph` using a shared `GlobalState`. The current graph follows a fixed sequence:

```text
Security Logs
     │
     ▼
┌──────────────┐
│ Log Parser   │
└──────┬───────┘
       ▼
┌────────────────────┐
│ Baseline Validator │
└────────┬───────────┘
         ▼
┌────────────────────┐
│ Incident Correlator│
└────────┬───────────┘
         ▼
┌────────────────────┐
│ Investigator Agent │
└────────┬───────────┘
         ▼
┌────────────────────┐
│ Report Generator   │
└────────┬───────────┘
         ▼
┌────────────────────┐
│ Email Notification │
└────────┬───────────┘
         ▼
        END
```

The graph currently contains the following nodes:

* **Parser** — loads authentication, DNS, firewall, and server logs.
* **Baseline Validator** — identifies anomalies such as excessive authentication failures, suspicious domains, unusual ports, possible port scanning, and abnormal HTTP activity.
* **Correlator** — groups anomalies by source IP and domain to form incidents.
* **Investigator Agent** — analyzes correlated incidents using Llama 3.3 and can use IP/DNS reputation tools when required.
* **Report Generator** — converts the investigation into a structured SOC report containing severity, findings, affected entities, IOCs, risk assessment, root-cause hypothesis, and recommended actions.
* **Mailer** — converts the Markdown report to HTML and sends it through Gmail SMTP.

---

## 🤖 AI Investigation

The investigator is the primary LLM-powered agent in the workflow.

It receives compressed correlated incident information and is instructed to:

* Identify suspicious IPs and domains
* Determine attack patterns
* Use reputation tools when required
* Determine the overall risk level
* Recommend SOC response actions

Two tools are currently provided to the agent:

```bash
ip_reputation
dns_reputation
```

The tools currently use local simulated threat-intelligence data. The code contains placeholders indicating that these can later be replaced with live sources such as VirusTotal, AlienVault OTX, or other reputation services.

---

## 🔍 Detection Capabilities

The baseline validation stage currently checks for:

* Authentication brute-force activity
* Suspicious DNS domains
* Excessive DNS queries
* Suspicious destination ports
* Possible port scanning
* Suspicious HTTP/C2 domains
* HTTP request floods

The thresholds are supplied when the workflow is started, allowing the detection baseline to be configured for the execution.

---

## 📊 Generated Report

The report generator produces a structured SOC incident report containing:

* Incident Title
* Severity Score
* Executive Summary
* Investigation Overview
* Key Findings
* Affected Systems / Entities
* Indicators of Compromise (IOCs)
* Risk Assessment
* Root Cause Hypothesis
* Recommended Actions for L2 Team
* Additional Notes

The report is generated in Markdown and is subsequently converted to HTML for email delivery.

---

## 💾 State & Persistence

LangGraph's `GlobalState` is used to carry information through the workflow, including parsed logs, baseline configuration, anomalies, incidents, investigations, and the final report.

SQLite is used as the LangGraph checkpointer, allowing workflow state to be persisted in:

```bash
src/app/memory/states.db
```

The graph is compiled with the SQLite checkpointer and is executed using a configured thread ID.

---

## ⚠️ POC Limitations

This project is currently a **Proof of Concept**.

The threat-intelligence tools use local simulated datasets rather than live external threat-intelligence APIs.

The workflow currently operates on sample log files stored inside the repository rather than a live SIEM or streaming security-event source.

The current LangGraph execution follows a predetermined sequence of nodes; the main agentic decision-making is performed inside the investigator agent through LLM reasoning and tool selection.

For production use, live SIEM integration, real threat-intelligence providers, stronger validation, authentication, monitoring, and additional security controls would be required.
