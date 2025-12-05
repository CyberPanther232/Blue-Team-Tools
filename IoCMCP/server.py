from mcp.server.fastmcp import FastMCP
import os
import requests

mcp = FastMCP("IoCMCP")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ABUSE_CH_AUTH_KEY = os.getenv("ABUSE_CH_AUTH_KEY")

@mcp.tool()
def virus_total_domain_lookup(domain: str, api_key: str = VIRUSTOTAL_API_KEY) -> dict:
    """
    Look up domain information using the VirusTotal API.

    Args:
        api_key (str): Your VirusTotal API key.
        domain (str): The domain to look up.

    Returns:
        dict: The JSON response from the VirusTotal API.
    """

    if not api_key:
        return {
            "error": "Missing VirusTotal API key",
            "hint": "Set environment variable 'VIRUSTOTAL_API_KEY' or pass 'api_key' explicitly."
        }

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        # Try JSON first; if it fails, return text body for debugging
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}
    except requests.exceptions.HTTPError as e:
        return {
            "error": "VirusTotal API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
        
@mcp.tool()
def virus_total_ip_lookup(ip: str, api_key: str = VIRUSTOTAL_API_KEY) -> dict:
    """
    Look up IP address information using the VirusTotal API.

    Args:
        api_key (str): Your VirusTotal API key.
        ip (str): The IP address to look up.

    Returns:
        dict: The JSON response from the VirusTotal API.
    """

    if not api_key:
        return {
            "error": "Missing VirusTotal API key",
            "hint": "Set environment variable 'VIRUSTOTAL_API_KEY' or pass 'api_key' explicitly."
        }
        
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        # Try JSON first; if it fails, return text body for debugging
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}
    except requests.exceptions.HTTPError as e:
        return {
            "error": "VirusTotal API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
    
@mcp.tool()
def virus_total_file_lookup(file_hash: str, api_key: str = VIRUSTOTAL_API_KEY) -> dict:
    """
    Look up file information using the VirusTotal API.

    Args:
        api_key (str): Your VirusTotal API key.
        file_hash (str): The file hash (MD5, SHA1, SHA256) to look up.

    Returns:
        dict: The JSON response from the VirusTotal API.
    """

    if not api_key:
        return {
            "error": "Missing VirusTotal API key",
            "hint": "Set environment variable 'VIRUSTOTAL_API_KEY' or pass 'api_key' explicitly."
        }
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        # Try JSON first; if it fails, return text body for debugging
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}
    except requests.exceptions.HTTPError as e:
        return {
            "error": "VirusTotal API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
    
@mcp.tool()
def virus_total_url_lookup(url: str, api_key: str = VIRUSTOTAL_API_KEY) -> dict:
    """
    Look up URL information using the VirusTotal API.
    Args:
        api_key (str): Your VirusTotal API key.
        url (str): The URL to look up.
    Returns:
        dict: The JSON response from the VirusTotal API.
    """
    
    if not api_key:
        return {
            "error": "Missing VirusTotal API key",
            "hint": "Set environment variable 'VIRUSTOTAL_API_KEY' or pass 'api_key' explicitly."
        }
    endpoint = "urls"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{url}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        # Try JSON first; if it fails, return text body for debugging
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}
    except requests.exceptions.HTTPError as e:
        return {
            "error": "VirusTotal API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
    
@mcp.tool()
def shodan_ip_lookup(ip: str, api_key: str=SHODAN_API_KEY) -> dict:
    """
    Look up IP address information using the Shodan API.
    Args:
        api_key (str): Your Shodan API key.
        ip (str): The IP address to look up.
    Returns:
        dict: The JSON response from the Shodan API.
    """
    
    if not api_key:
        return {
            "error": "Missing Shodan API key",
            "hint": "Pass 'api_key' explicitly."
        }
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Shodan API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
        
def shodan_domain_lookup(domain: str, api_key: str=SHODAN_API_KEY) -> dict:
    """
    Look up domain information using the Shodan API.
    Args:
        api_key (str): Your Shodan API key.
        domain (str): The domain to look up.
    Returns:
        dict: The JSON response from the Shodan API.
    """
    
    if not api_key:
        return {
            "error": "Missing Shodan API key",
            "hint": "Pass 'api_key' explicitly."
        }
    url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Shodan API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
        
def shodan_host_search(query: str, api_key: str=SHODAN_API_KEY) -> dict:
    """
    Search hosts using the Shodan API.
    Args:
        api_key (str): Your Shodan API key.
        query (str): The search query.
    Returns:
        dict: The JSON response from the Shodan API.
    """
    
    if not api_key:
        return {
            "error": "Missing Shodan API key",
            "hint": "Pass 'api_key' explicitly."
        }
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Shodan API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
        
@mcp.tool()
def shodan_exploit_lookup(cve_id: str, api_key: str=SHODAN_API_KEY) -> dict:
    """
    Look up exploit information using the Shodan Exploits API.
    Args:
        api_key (str): Your Shodan API key.
        cve_id (str): The CVE identifier to look up.
    Returns:
        dict: The JSON response from the Shodan Exploits API.
    """
    
    if not api_key:
        return {
            "error": "Missing Shodan API key",
            "hint": "Pass 'api_key' explicitly."
        }
    url = f"https://exploits.shodan.io/api/exploits/{cve_id}?key={api_key}"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Shodan Exploits API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
    
@mcp.tool()
def abuse_ch_ip_lookup(ip: str, api_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up IP address information using the Abuse.ch API.
    Args:
        api_key (str): Your Abuse.ch API key.
        ip (str): The IP address to look up.
    Returns:
        dict: The JSON response from the Abuse.ch API.
    """
    
    if not api_key:
        return {
            "error": "Missing Abuse.ch API key",
            "hint": "Pass 'api_key' explicitly."
        }
    url = "https://abuse.ch/api/v1/"
    data = {
        "query": "get_ip_info",
        "ip": ip,
        "auth_key": api_key
    }
    try:
        response = requests.post(url, data=data, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Abuse.ch API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
        
@mcp.tool()
def abuse_ch_domain_lookup(domain: str, api_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up domain information using the Abuse.ch API.
    Args:
        api_key (str): Your Abuse.ch API key.
        domain (str): The domain to look up.
    Returns:
        dict: The JSON response from the Abuse.ch API.
    """
    
    if not api_key:
        return {
            "error": "Missing Abuse.ch API key",
            "hint": "Pass 'api_key' explicitly."
        }
    url = "https://abuse.ch/api/v1/"
    data = {
        "query": "get_domain_info",
        "domain": domain,
        "auth_key": api_key
    }
    try:
        response = requests.post(url, data=data, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Abuse.ch API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
        
@mcp.tool()
def abuse_ch_file_lookup(file_hash: str, api_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up file information using the Abuse.ch API.
    Args:
        api_key (str): Your Abuse.ch API key.
        file_hash (str): The file hash (MD5, SHA1, SHA256) to look up.
    Returns:
        dict: The JSON response from the Abuse.ch API.
    """
    if not api_key:
        return {
            "error": "Missing Abuse.ch API key",
            "hint": "Pass 'api_key' explicitly."
        }
    url = "https://abuse.ch/api/v1/"
    data = {
        "query": "get_file_info",
        "hash": file_hash,
        "auth_key": api_key
    }
    try:
        response = requests.post(url, data=data, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Abuse.ch API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
        
@mcp.tool()
def abuse_ch_url_lookup(url: str, api_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up URL information using the Abuse.ch API.
    Args:
        api_key (str): Your Abuse.ch API key.
        url (str): The URL to look up.
    Returns:
        dict: The JSON response from the Abuse.ch API.
    """
    if not api_key:
        return {
            "error": "Missing Abuse.ch API key",
            "hint": "Pass 'api_key' explicitly."
        }
    api_url = "https://abuse.ch/api/v1/"
    data = {    
        "query": "get_url_info",
        "url": url,
        "auth_key": api_key
    }
    try:
        response = requests.post(api_url, data=data, timeout=15)
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Abuse.ch API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }


@mcp.tool()
def threat_fox_ip_lookup(ip: str, auth_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up IP address information using the ThreatFox API.

    Args:
        ip (str): The IP address to look up.

    Returns:
        dict: The JSON response from the ThreatFox API.
    """

    url = f"https://threatfox.abuse.ch/api/v1/ip/{ip}"
    headers = {"Auth-Key": auth_key} if auth_key else {}
    
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "ThreatFox API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }


@mcp.tool()
def malware_bazaar_file_lookup(file_hash: str) -> dict:
    """
    Look up file information using the MalwareBazaar API.

    Args:
        file_hash (str): The file hash (MD5, SHA1, SHA256) to look up.

    Returns:
        dict: The JSON response from the MalwareBazaar API.
    """

    url = "https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_info",
        "hash": file_hash
    }
    try:
        response = requests.post(url, data=data, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "MalwareBazaar API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }

@mcp.tool()
def urlhaus_url_lookup(url: str) -> dict:
    """
    Look up URL information using the URLhaus API.

    Args:
        url (str): The URL to look up.

    Returns:
        dict: The JSON response from the URLhaus API.
    """
    api_url = "https://urlhaus.abuse.ch/api/"
    try:
        response = requests.post(api_url, data={"query": "get_url", "url": url}, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "URLhaus API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }

@mcp.tool()
def otx_indicator_lookup(indicator: str, api_key: str) -> dict:
    """
    Look up indicator (IP, domain, URL, hash) using AlienVault OTX.

    Args:
        api_key (str): Your AlienVault OTX API key.
        indicator (str): The indicator value.

    Returns:
        dict: The JSON from OTX API.
    """

    if not api_key:
        return {
            "error": "Missing OTX API key",
            "hint": "Pass 'api_key' explicitly."
        }

    # Try to detect type via simple heuristics
    if "://" in indicator:
        endpoint = f"indicators/url/url/{indicator}"
    elif "." in indicator and all(ch.isdigit() or ch=='.' for ch in indicator):
        endpoint = f"indicators/IPv4/{indicator}"
    elif "." in indicator:
        endpoint = f"indicators/domain/{indicator}"
    else:
        endpoint = f"indicators/file/{indicator}"

    url = f"https://otx.alienvault.com/api/v1/{endpoint}"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "OTX API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
if __name__ == "__main__":
    mcp.run(transport="stdio")