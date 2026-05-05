import urllib.request
import logging
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
from .utils import get_id_token

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


def search_web_for_iocs(keywords: str) -> str:
    """Searches the web for IOCs based on keywords.
    
    Args:
        keywords: The keywords to search for.
    Returns:
        Simulated search results containing IOCs.
    """
    print(f"[Tool: Search Web] Searching for keywords: {keywords}")
    # Simulated result
    return """
    Search Results for Vercel Security Incident April 2026:
    - Article 1: 'Vercel incident analysis'. Mentioned malicious IP: 192.168.1.100 and domain: attacker-site.net.
    - Article 2: 'Context.ai compromise details'. Mentioned hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
    """


def create_mcp_toolset(url: str) -> McpToolset:
    if not url:
        raise ValueError("MCP URL cannot be None")
        
    if url.startswith("http://localhost") or url.startswith("http://127.0.0.1"):
        logger.info(f"Connecting to local MCP server at {url}")
        params = StreamableHTTPConnectionParams(url=url)
    else:
        logger.info(f"Connecting to remote MCP server at {url}")
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        audience = f"{parsed_url.scheme}://{parsed_url.netloc}"
        token = get_id_token(audience)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        params = StreamableHTTPConnectionParams(url=url, headers=headers)
        
    return McpToolset(connection_params=params)
