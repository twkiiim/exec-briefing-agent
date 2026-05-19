import urllib.request
import logging
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams

logger = logging.getLogger(__name__)



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
        
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    audience = f"{parsed_url.scheme}://{parsed_url.netloc}"

    def dynamic_jwt_header_provider(session_state):
        print(f"[Header Provider] Fetching token for audience: {audience}")
        from .utils import get_id_token
        token = get_id_token(audience)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return headers

    if url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
        logger.info(f"Connecting to local MCP server at {url}")
        params = StreamableHTTPConnectionParams(url=url)
        return McpToolset(connection_params=params)
    else:
        logger.info(f"Connecting to remote MCP server at {url}")
        params = StreamableHTTPConnectionParams(url=url)
        return McpToolset(connection_params=params, header_provider=dynamic_jwt_header_provider)
