import os
import logging
from dotenv import load_dotenv
from google.adk.agents.llm_agent import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from google.adk.tools import FunctionTool
from .tools import (
    fetch_url_content,

    create_mcp_toolset,
    search_web_for_iocs
)

logger = logging.getLogger(__name__)
logging.basicConfig(format="[%(levelname)s]: %(message)s", level=logging.INFO)

# Load .env
load_dotenv()

# Get MCP URLs from environment
gti_mcp_server_url = os.getenv("GTI_MCP_URL")
secops_mcp_server_url = os.getenv("SECOPS_MCP_URL")


# 1. Article Analyzer
ioc_searcher = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="ioc_searcher",
    description="Searches for IOCs based on provided keywords.",
    instruction="""Use the `search_web_for_iocs` tool to search for more information about the security incident using the keywords provided in the input.
    Look for articles or blog posts that might contain specific Indicators of Compromise (IOCs) like IPs, domains, hashes, or URLs.
    You MUST verify that the searched pages are talking about the EXACT SAME incident and are temporally connected (same time frame).
    
    Then, extract the IOCs in the following JSON structure:
    {{
      "iocs": {{
        "ip": [...],
        "domain": [...],
        "hash": [...],
        "url": [...],
        "other_identifiers": [...]
      }},
      "summary": "Combined summary including new findings",
      "status": "SUCCESS"
    }}
    If no IOCs are found, set the "iocs" object to empty lists and set "status" to "NO_IOCS_FOUND".
    Output ONLY the JSON object.""",
    tools=[search_web_for_iocs],
    output_key="analysis_result"
)

async def search_iocs_via_agent(keywords: str) -> str:
    """Searches for IOCs using the ioc_searcher agent.
    
    Args:
        keywords: The keywords to search for.
    Returns:
        JSON string with IOCs.
    """
    print(f"[Tool: Agent Tool] Running ioc_searcher with keywords: {keywords}")
    final_text = ""
    try:
        async for event in ioc_searcher.run_live(f"Keywords: {keywords}"):
            if hasattr(event, 'name') and event.name == 'Output-Agent':
                if hasattr(event, 'content') and 'parts' in event.content:
                    for part in event.content['parts']:
                        if 'text' in part:
                            final_text += part['text']
    except Exception as e:
        print(f"Error in search_iocs_via_agent: {e}")
        return f"Error running ioc_searcher: {e}"
        
    return final_text

keyword_extractor = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="keyword_extractor",
    description="Extracts keywords and decides whether to search for IOCs.",
    instruction="""Use the `fetch_url_content` tool to read the content of the provided URL.
    Then, analyze the content to extract key keywords and a comprehensive summary of the security event.
    
    Decide if it is necessary to search for more IOCs on the web.
    If YES, use the `search_iocs_via_agent` tool to search for IOCs using the extracted keywords. The `search_iocs_via_agent` will provide the final JSON result.
    If NO, you must generate the JSON result yourself with the following structure:
    {{
      "iocs": {{
        "ip": [],
        "domain": [],
        "hash": [],
        "url": [],
        "other_identifiers": []
      }},
      "summary": "Summary from original page",
      "status": "SUCCESS"
    }}
    Output ONLY the JSON object if you do not call search_iocs_via_agent.""",
    tools=[fetch_url_content, FunctionTool(search_iocs_via_agent)],
    output_key="analysis_result"
)

# 2. Investigator
# Refer to the output of the previous agent using the {analysis_result} placeholder.
investigator = Agent(
    model='gemini-3.1-flash-lite-preview',
    name="investigator",
    description="Investigates security events using tools.",
    instruction="""Given the analysis result: {analysis_result}.
    The analysis result is a JSON string.
    If the "status" is "NO_IOCS_FOUND" or if there are no IOCs in all categories, do NOT use any tools. Simply output 'Workflow terminated: No IOCs found to investigate.'
    Otherwise, for EACH IOC listed in the "iocs" object (across all categories), you MUST use the available MCP tools (Google Threat Intelligence and SecOps) to check for related threat intelligence or compromise data.
    You MUST execute tool calls for every identified IOC. Do not just summarize without calling tools.
    Summarize the findings from all tools used for all IOCs.""",
    tools=[
        create_mcp_toolset(gti_mcp_server_url),
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
    description="Runs the full hunting workflow: extracts keywords and dynamically searches for IOCs, investigates findings, and consolidates results.",
    sub_agents=[keyword_extractor, investigator, consolidator]
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

