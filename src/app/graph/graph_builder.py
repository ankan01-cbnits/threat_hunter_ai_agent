import sqlite3
from langgraph.checkpoint. import SQLiteSaver
from langgraph.graph import StateGraph,START,END
from .states.__global import GlobalState
from ..tools.parse_logs import parse_all_logs
from ...baseline.baseline_validator import baseline_validator

db_path = "memory/states.db"
conn = sqlite3.connect(db_path, check_same_thread=False)
sql_memory = SqliteSaver(conn)

graph_builder = StateGraph(GlobalState)


graph_builder.add_node("parser",parse_all_logs)
graph_builder.add_node("baseline_validator",baseline_validator)
# graph_builder.add_node("investigator",investigator_agent)
# graph_builder.add_node("correlator",corr_agent)
# graph_builder.add_node("reporter",report_generator)


graph_builder.add_edge(START,"parser")
graph_builder.add_edge("parser","baseline_validator")
graph_builder.add_edge("baseline_validator",END)

runnable_graph=graph_builder.compile(checkpointer=sql_memory)
runnable_graph.invoke({ })