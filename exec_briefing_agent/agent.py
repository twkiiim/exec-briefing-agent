import os
import logging
from dotenv import load_dotenv
from google.adk.agents.llm_agent import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from .tools import (
    fetch_url_content,
    create_mcp_toolset
)

logger = logging.getLogger(__name__)
logging.basicConfig(format="[%(levelname)s]: %(message)s", level=logging.INFO)

# Load .env
load_dotenv()

# Get MCP URLs from environment
gti_mcp_server_url = os.getenv("GTI_MCP_URL")
secops_mcp_server_url = os.getenv("SECOPS_MCP_URL")


# 1. Keyword Extractor
keyword_extractor = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="keyword_extractor",
    description="Extracts keywords from URL content.",
    instruction="""Use the `fetch_url_content` tool to read the content of the provided URL.
    Then, analyze the content to extract key keywords and a comprehensive summary of the security event.
    Output the keywords and summary.
    
    ## RULE ##
    At the end of your response, you must accurately list ONLY the tools you specifically invoked to answer the CURRENT query in this turn.
    For each tool used, you must specify:
    1. The name of the tool.
    2. The arguments used for the call.
    3. The source or MCP server it belongs to (e.g., 'Local Function').
    If you did not use any tools for this specific response, you must clearly state that you did not use any tools.""",
    tools=[fetch_url_content],
    output_key="keyword_extraction_result"
)

# 1.5 IOC Collector
ioc_collector = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="ioc_collector",
    description="Searches GTI for IOCs using keywords.",
    instruction="""Given the keyword extraction result from the previous step: {keyword_extraction_result}.
    Use the extracted keywords to search for related Indicators of Compromise (IOCs) in the Google Threat Intelligence platform using the `search_iocs` tool.
    Extract domains, IPs, URLs, and hashes found in the search results.
    
    Output the findings in the following JSON structure:
    {{
      "iocs": {{
        "ip": [...],
        "domain": [...],
        "hash": [...],
        "url": [...],
        "other_identifiers": [...]
      }},
      "summary": "Summary of the security event",
      "status": "SUCCESS"
    }}
    If no IOCs are found in GTI, set the "iocs" object to empty lists and set "status" to "NO_IOCS_FOUND".
    Output ONLY the JSON object.
    
    ## RULE ##
    At the end of your response, you must accurately list ONLY the tools you specifically invoked to answer the CURRENT query in this turn.
    For each tool used, you must specify:
    1. The name of the tool.
    2. The arguments used for the call.
    3. The source or MCP server it belongs to (e.g., 'GTI MCP').
    If you did not use any tools for this specific response, you must clearly state that you did not use any tools.""",
    tools=[create_mcp_toolset(gti_mcp_server_url)],
    output_key="analysis_result"
)

# 2. Investigator (SecOps only)
# Refer to the output of the previous agent using the {analysis_result} placeholder.
investigator = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="investigator",
    description="Investigates security events using SecOps tools.",
    instruction="""Given the analysis result: {analysis_result}.
    The analysis result contains a JSON string with extracted IOCs.
    If the "status" is "NO_IOCS_FOUND" or if there are no IOCs in all categories, do NOT use any tools. Simply output 'Workflow terminated: No IOCs found to investigate.'
    Otherwise, for EACH IOC listed in the "iocs" object (across all categories), you MUST use the available Google SecOps MCP tools to check for related security events, alerts, or logs in your environment.
    You MUST execute tool calls for every identified IOC. Do not just summarize without calling tools.
    Summarize the findings from SecOps for all IOCs.
    
    ## RULE ##
    At the end of your response, you must accurately list ONLY the tools you specifically invoked to answer the CURRENT query in this turn.
    For each tool used, you must specify:
    1. The name of the tool.
    2. The arguments used for the call.
    3. The source or MCP server it belongs to (e.g., 'SecOps MCP').
    If a tool name is generic like 'default_api.search', make sure to identify its source server correctly based on the context or the toolset it belongs to.
    Do not list tools used in previous turns or tools that you did not actually call for this specific response.
    If you did not use any tools for this specific response, you must clearly state that you did not use any tools.""",
    tools=[
        create_mcp_toolset(secops_mcp_server_url)
    ],
    output_key="investigation_result"
)

# 3. Consolidator
# Refer to the output of the previous agent using the {investigation_result} placeholder.
consolidator = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="consolidator",
    description="Consolidates findings and answers Yes/No.",
    instruction="""Given the investigation result: {investigation_result}.
    If the investigation result indicates that the workflow was terminated due to no IOCs, answer:
    1. Reported internally?: N/A (No IOCs found to investigate)
    2. Key findings summary: The source page did not contain any identifiable IOCs, so internal investigation could not be performed.
    Otherwise, consolidate the findings and answer:
    1. Reported internally?: (Yes or No)
    2. Key findings summary.
    Answer Yes if any exposed assets or internal compromise was found, otherwise No.""",
)

# Bind the full flow with a sequential agent (changed to workflow)
hunting_workflow = SequentialAgent(
    name="hunting_workflow",
    description="Runs the full hunting workflow: extracts keywords, searches GTI for IOCs, investigates findings, and consolidates results.",
    sub_agents=[keyword_extractor, ioc_collector, investigator, consolidator]
)

# New root_agent (Regular Agent)
root_agent = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="root_agent",
    description="Root agent that handles user requests and decides when to run the hunting workflow.",
    instruction="""You are the root agent.
    Your task is to handle user requests.
    If the user provides a page URL for a security incident or vulnerability, you MUST transfer control to the `hunting_workflow` sub-agent to process it.
    Do not attempt to analyze the URL yourself or use other tools. Just pass the URL to `hunting_workflow`.
    If the user does not provide a URL or asks about other things, respond politely stating that you need a URL to start the investigation.""",
    sub_agents=[hunting_workflow]
)
