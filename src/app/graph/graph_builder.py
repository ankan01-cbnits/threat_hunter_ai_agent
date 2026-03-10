import sqlite3
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import StateGraph,START,END

from app.agents.correlation_agent import correlation_agent
from app.agents.generate_incident_report import generate_incident_report
from app.agents.investigator import investigator_agent
from app.agents.mailer import mailer_agent

from .states.__global import GlobalState
from app.tools.parse_logs import parse_all_logs
from src.baseline.baseline_validator import baseline_validator 

db_path = "src/app/memory/states.db"
conn = sqlite3.connect(db_path, check_same_thread=False)
sql_memory = SqliteSaver(conn)

graph_builder = StateGraph(GlobalState)


graph_builder.add_node("parser",parse_all_logs)
graph_builder.add_node("baseline_validator",baseline_validator)
graph_builder.add_node("investigator",investigator_agent)
graph_builder.add_node("correlator",correlation_agent)
graph_builder.add_node("mailer",mailer_agent)
graph_builder.add_node("reporter",generate_incident_report)


graph_builder.add_edge(START,"parser")
graph_builder.add_edge("parser","baseline_validator")
graph_builder.add_edge("baseline_validator","correlator")
graph_builder.add_edge("correlator","investigator")
graph_builder.add_edge("investigator","reporter")
graph_builder.add_edge("reporter","mailer")
graph_builder.add_edge("mailer",END)


runnable_graph=graph_builder.compile(checkpointer=sql_memory)

def graph_compiler():
    return runnable_graph
