import requests
from bs4 import BeautifulSoup
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scrape_web(query, max_results=5, domain="general"):
    """
    Scrape web results for a given query, optionally filtered by domain.
    
    Args:
        query (str): The search query.
        max_results (int): Maximum number of results to return.
        domain (str): The domain to focus the search on (e.g., 'sport', 'technology').
    
    Returns:
        list: A list of dictionaries containing text and URL of search results.
    """
    url = "https://lite.duckduckgo.com/lite/"
    # If domain is not 'general', append it to the query to narrow the search
    if domain != "general":
        query = f"{query} {domain}"
    params = {"q": query}
    
    try:
        # Set a user-agent to avoid being blocked
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.post(url, data=params, headers=headers)
        response.raise_for_status()
        logger.info(f"Successfully fetched results for query: {query}")
    except requests.RequestException as e:
        logger.error(f"Scraping error for query '{query}': {e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    results = []

    for result in soup.find_all("a", class_="result-link", limit=max_results):
        text = result.get_text(strip=True)
        href = result.get("href")
        if text and href:
            results.append({
                "text": text,
                "url": href
            })
    
    logger.info(f"Retrieved {len(results)} results for query: {query}")
    return results