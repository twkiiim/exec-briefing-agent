import urllib.request
import logging
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from .utils import get_id_token

logger = logging.getLogger(__name__)

def investigation_tool_internal_logs() -> str:
    """검색 로그에서 CVE 관련 내용을 조회합니다."""
    print("[Tool: Internal Logs] Searching...")
    return "Internal Logs Finding: No exploitation attempts found."

def investigation_tool_threat_intel() -> str:
    """위협 인텔리전스 정보를 조회합니다."""
    print("[Tool: Threat Intel] Searching...")
    return "Threat Intel Finding: Active exploitation seen by APT-X."

def investigation_tool_asset_db() -> str:
    """자산 DB에서 취약한 버전을 사용하는 자산을 조회합니다."""
    print("[Tool: Asset DB] Searching...")
    return "Asset DB Finding: 5 exposed Apache servers found."

def fetch_url_content(url: str) -> str:
    """Fetches the content of a given URL.
    
    Args:
        url: The URL to fetch.
    Returns:
        The raw content of the URL as a string.
    """
    print(f"[Tool: Fetch URL] Fetching {url}")
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0'} # Add user agent to avoid some blocks
        )
        with urllib.request.urlopen(req) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        return f"Error fetching URL: {e}"

def create_mcp_toolset(url: str) -> McpToolset:
    if not url:
        raise ValueError("MCP URL cannot be None")
        
    if url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
        logger.info(f"Connecting to local MCP server at {url}")
        params = StreamableHTTPConnectionParams(url=url)
    else:
        logger.info(f"Connecting to remote MCP server at {url}")
        token = get_id_token(url)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        params = StreamableHTTPConnectionParams(url=url, headers=headers)
        
    return McpToolset(connection_params=params)
