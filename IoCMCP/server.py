from mcp.server.fastmcp import FastMCP
import os
import requests

mcp = FastMCP("IoCMCP")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ABUSE_CH_AUTH_KEY = os.getenv("ABUSE_CH_AUTH_KEY")

########################################################
################### VirusTotal Tools ###################
########################################################

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
    
########################################################
##################### Shodan Tools #####################
########################################################

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

@mcp.tool()
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

@mcp.tool()
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
    
########################################################
################### ThreatFox Tools ####################
########################################################

@mcp.tool()
def threat_fox_ioc_lookup(ioc: str, auth_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up IP address information using the ThreatFox API.

    Args:
        auth_key (str): Your ThreatFox API key.
        ioc (str): The indicator of compromise (IOC) to look up.

    Returns:
        dict: The JSON response from the ThreatFox API.
    """

    url = f"https://threatfox.abuse.ch/api/v1/"
    data = {
        "query": "search_ioc",
        "search_term": ioc,
        "exact_match": "true"
    }
    headers = {"Auth-Key": auth_key} if auth_key else {}
    
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=15)
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
def threat_fox_file_hash_lookup(file_hash: str, auth_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up file information using the ThreatFox API.

    Args:
        auth_key (str): Your ThreatFox API key.
        file_hash (str): The file hash to look up. Md5 or Sha256.

    Returns:
        dict: The JSON response from the ThreatFox API.
    """
    def detect_hash_type(h: str) -> str:
        if len(h) == 32:
            return "md5"
        elif len(h) == 64:
            return "sha256"
        else:
            return "unknown"
    
    hash_type = detect_hash_type(file_hash)
    if hash_type == "unknown":
        return {
            "error": "Unsupported hash type",
            "details": "Only MD5 and SHA256 hashes are supported."
        }
    
    url = f"https://threatfox.abuse.ch/api/v1/"
    data = {
        "query": "search_hash",
        "hash": file_hash
    }
    
    headers = {"Auth-Key": auth_key} if auth_key else {}
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=15)
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

def threat_fox_malware_lookup(malware_name: str, auth_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up malware information using the ThreatFox API.

    Args:
        auth_key (str): Your ThreatFox API key.
        malware_name (str): The malware name to look up.

    Returns:
        dict: The JSON response from the ThreatFox API.
    """
    
    url = f"https://threatfox.abuse.ch/api/v1/"
    data = {
        "query": "malwareinfo",
        "malware": malware_name
        "limit" : 5
    }
    
    headers = {"Auth-Key": auth_key} if auth_key else {}
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=15)
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

########################################################
################ Malware Bazaar Tools ##################
########################################################

def malware_bazaar_hash_lookup(file_hash: str, auth_key: str=ABUSE_CH_AUTH_KEY) -> dict:
    """
    Look up file information using the Malware Bazaar API.

    Args:
        auth_key (str): Your Malware Bazaar API key.
        file_hash (str): The file hash to look up. Md5 or Sha256.

    Returns:
        dict: The JSON response from the Malware Bazaar API.
    """
    
    
    url = f"https://mb-api.abuse.ch/api/v1/"
    data = {
        "query": "get_info",
        "hash": file_hash
    }
    
    headers = {"Auth-Key": auth_key} if auth_key else {}
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": "Malware Bazaar API HTTP error",
            "status_code": response.status_code if 'response' in locals() and response is not None else None,
            "details": str(e),
            "body": getattr(response, 'text', None)
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
    
    
    

########################################################
#################### OTX Tools #########################
########################################################

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
        
#########################################################
################# HaveIBeenPwned Tools ##################
#########################################################

@mcp.tool()
def hibp_breach_lookup(breach_name: str) -> dict:
    
    import beautifulsoup4 as bs4
    
    """
    Look up breach information using the HaveIBeenPwned API.
    Args:
        breach_name (str): The name of the breach to look up.
    Returns:
        dict: The JSON response from the HaveIBeenPwned Website.
    """
    
    url = "https://haveibeendpwned.com/PwnedWebsites"
    
    breach_data = {}
    
    try:
        content = requests.get(url, timeout=15, headers={"User-Agent": "IoCMCP-Tool"})
        soup = bs4.BeautifulSoup(content.text, 'html.parser')
        table = soup.find('table', {'id': 'breachesTable'})
        rows = table.find_all('tr')[1:]  # Skip header row
        
        for row in rows:
            cols = row.find_all('td')
            breach = cols[0].text.strip()
            pwncount = cols[1].text.strip()
            date = cols[2].text.strip()
            breachDate = cols[3].text.strip()
            
            if breach == breach_name:
                return {
                    "breach": breach,
                    "pwncount": pwncount,
                    "date": date,
                    "breachDate": breachDate
                }

        else:
            return {
                "error": "HaveIBeenPwned Website HTTP error",
                "status_code": content.status_code,
                "body": content.text
            }
    except requests.exceptions.RequestException as e:
        return {
            "error": "Network or request error",
            "details": str(e)
        }
    

        
if __name__ == "__main__":
    mcp.run(transport="stdio")