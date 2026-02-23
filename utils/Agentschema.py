from typing import TypedDict, Annotated, List
from operator import add
from langchain_core.messages import BaseMessage

class VAPTState(TypedDict):
    repo_url: str
    branch_name:str
    repo_path: str
    access_token: str
    node_results: str
    final_report:str
    file_struct_path:str
    tech_stack:List[str]
    messages: Annotated[List[BaseMessage], add]
    sender:str
    v1_msgs: Annotated[List[BaseMessage], add]
    v2_msgs: Annotated[List[BaseMessage], add]
    v3_msgs: Annotated[List[BaseMessage], add]
    v4_msgs: Annotated[List[BaseMessage], add]
    v5_msgs: Annotated[List[BaseMessage], add]
    v6_msgs: Annotated[List[BaseMessage], add]
    v7_msgs: Annotated[List[BaseMessage], add]
    v8_msgs: Annotated[List[BaseMessage], add]
    v9_msgs: Annotated[List[BaseMessage], add]
    v10_msgs: Annotated[List[BaseMessage], add]
    
   

