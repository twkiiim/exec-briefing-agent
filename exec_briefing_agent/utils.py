import logging
import google.auth
import google.auth.transport.requests
from google.oauth2 import id_token

logger = logging.getLogger(__name__)

def get_id_token(url: str) -> str | None:
    """Gets a Google ID token for the given audience (URL)."""
    logger.info(f"Attempting to get ID token for audience: {url}")
    try:
        auth_req = google.auth.transport.requests.Request()
        return id_token.fetch_id_token(auth_req, url)
    except Exception as e:
        logger.warning(f"Failed to get ID token: {e}")
        return None
