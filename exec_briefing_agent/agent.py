import os
import logging
from dotenv import load_dotenv
from google.adk.agents.llm_agent import Agent
from google.adk.agents.sequential_agent import SequentialAgent
from .tools import (
    fetch_url_content,
    investigation_tool_internal_logs,
    investigation_tool_threat_intel,
    investigation_tool_asset_db,
    create_mcp_toolset,
    search_web_for_iocs
)

logger = logging.getLogger(__name__)
logging.basicConfig(format="[%(levelname)s]: %(message)s", level=logging.INFO)

# Load .env
load_dotenv()

# Get MCP URLs from environment
gti_mcp_url = os.getenv("GTI_MCP_URL", "https://stg-gti-mcp-ic427jowfa-uc.a.run.app/mcp")
secops_mcp_url = os.getenv("SECOPS_MCP_URL", "https://stg-secops-mcp-ic427jowfa-uc.a.run.app/mcp")


# 에이전트 정의

# 1. Article Analyzer
# fetch_url_content 도구를 사용하여 URL 내용을 가져옵니다.
ioc_searcher = Agent(
    model='gemini-2.5-flash',
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

keyword_extractor = Agent(
    model='gemini-2.5-flash',
    name="keyword_extractor",
    description="Extracts keywords and decides whether to search for IOCs.",
    instruction="""Use the `fetch_url_content` tool to read the content of the provided URL.
    Then, analyze the content to extract key keywords and a comprehensive summary of the security event.
    
    Decide if it is necessary to search for more IOCs on the web.
    If YES, use the `ioc_searcher` tool to search for IOCs using the extracted keywords. The `ioc_searcher` will provide the final JSON result.
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
    Output ONLY the JSON object if you do not call ioc_searcher.""",
    tools=[fetch_url_content, ioc_searcher],
    output_key="analysis_result"
)

# 2. Investigator
# {analysis_result} 플레이스홀더를 사용하여 이전 에이전트의 출력을 참조합니다.
investigator_tools = [
    investigation_tool_internal_logs,
    investigation_tool_threat_intel,
    investigation_tool_asset_db
]

# Try to add MCP tools if URLs are available
# try:
#     logger.info(f"Adding GTI MCP tools from {gti_mcp_url}")
#     investigator_tools.append(create_mcp_toolset(gti_mcp_url))
# except Exception as e:
#     logger.warning(f"Failed to add GTI MCP tools: {e}")

# try:
#     logger.info(f"Adding SecOps MCP tools from {secops_mcp_url}")
#     investigator_tools.append(create_mcp_toolset(secops_mcp_url))
# except Exception as e:
#     logger.warning(f"Failed to add SecOps MCP tools: {e}")

investigator = Agent(
    model='gemini-2.5-flash',
    name="investigator",
    description="Investigates security events using tools.",
    instruction="""Given the analysis result: {analysis_result}.
    The analysis result is a JSON string.
    If the "status" is "NO_IOCS_FOUND" or if there are no IOCs in all categories, do NOT use any tools. Simply output 'Workflow terminated: No IOCs found to investigate.'
    Otherwise, for EACH IOC listed in the "iocs" object (across all categories), you MUST use the available tools to check if there is any related internal compromise data or threat intelligence.
    You have access to internal logs, threat intel, and asset DB dummy tools, as well as real MCP tools for Google Threat Intelligence and SecOps if available.
    Summarize the findings from all tools used for all IOCs.""",
    tools=investigator_tools,
    output_key="investigation_result"
)

# 3. Consolidator
# {investigation_result} 플레이스홀더를 사용하여 이전 에이전트의 출력을 참조합니다.
consolidator = Agent(
    model='gemini-2.5-flash',
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

# 순차 에이전트로 전체 흐름 묶기 (워크플로우로 변경)
hunting_workflow = SequentialAgent(
    name="hunting_workflow",
    description="Runs the full hunting workflow: extracts keywords and dynamically searches for IOCs, investigates findings, and consolidates results.",
    sub_agents=[keyword_extractor, investigator, consolidator]
)

# 새로운 root_agent (일반 Agent)
root_agent = Agent(
    model='gemini-2.5-flash',
    name="root_agent",
    description="Root agent that handles user requests and decides when to run the hunting workflow.",
    instruction="""You are the root agent.
    Your task is to handle user requests.
    If the user provides a page URL for a security incident or vulnerability, you MUST transfer control to the `hunting_workflow` sub-agent to process it.
    Do not attempt to analyze the URL yourself or use other tools. Just pass the URL to `hunting_workflow`.
    If the user does not provide a URL or asks about other things, respond politely stating that you need a URL to start the investigation.""",
    sub_agents=[hunting_workflow]
)

