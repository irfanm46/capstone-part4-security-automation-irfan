import os
import re
import sys
import json
import argparse
from typing import Set, Dict, Any, Optional
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def is_private_ip(ip_str: str) -> bool:
    """
    Evaluates whether an IPv4 address falls within standard RFC 1918 private ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
    - 192.168.0.0/16
    """
    try:
        octets = [int(octet) for octet in ip_str.split(".")]
        if len(octets) != 4:
            return True

        # 10.0.0.0/8
        if octets[0] == 10:
            return True

        # 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True

        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True

        # Loopback 127.0.0.0/8 and APIPA 169.254.0.0/16
        if octets[0] == 127 or (octets[0] == 169 and octets[1] == 254):
            return True

        return False
    except ValueError:
        return True


def extract_public_ips(file_path: str) -> Set[str]:
    """
    Reads a plain-text log file, extracts all IPv4 addresses matching dotted-decimal notation,
    filters out private ranges, and returns a deduplicated set of public IPs.
    """
    # Regex matching four groups of 1-3 digits separated by dots
    ip_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
    public_ips: Set[str] = set()

    if not os.path.exists(file_path):
        print(f"[-] Error: Log file '{file_path}' does not exist.")
        sys.exit(1)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                found_ips = ip_pattern.findall(line)
                for ip in found_ips:
                    if not is_private_ip(ip):
                        public_ips.add(ip)
    except OSError as e:
        print(f"[-] Error reading file '{file_path}': {e}")
        sys.exit(1)

    return public_ips


def query_ip_api(ip: str) -> Dict[str, Any]:
    """Queries ip-api.com REST API for geolocation and network metadata."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,proxy,hosting,mobile,query"
    enrichment = {
        "country": "Unknown",
        "isp": "Unknown",
        "is_hosting": False,
        "is_proxy": False,
        "is_mobile": False,
        "api_status": "failed"
    }

    try:
        response = requests.get(url, timeout=5.0)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "success":
            enrichment["country"] = data.get("country", "Unknown")
            enrichment["isp"] = data.get("isp", "Unknown")
            enrichment["is_hosting"] = bool(data.get("hosting", False))
            enrichment["is_proxy"] = bool(data.get("proxy", False))
            enrichment["is_mobile"] = bool(data.get("mobile", False))
            enrichment["api_status"] = "success"
        else:
            enrichment["api_status"] = f"api_error: {data.get('message', 'query failed')}"
    except requests.exceptions.RequestException as e:
        enrichment["api_status"] = f"http_error: {str(e)}"
    except json.JSONDecodeError:
        enrichment["api_status"] = "json_parse_error"

    return enrichment


def query_virustotal(ip: str, api_key: Optional[str]) -> Dict[str, Any]:
    """Queries VirusTotal API v3 for threat detection statistics."""
    vt_result = {
        "vt_malicious_detections": 0,
        "vt_harmless_count": 0,
        "vt_last_analysis_date": "N/A",
        "vt_status": "skipped"
    }

    if not api_key or api_key.strip() == "" or api_key == "your_virustotal_api_key_here":
        vt_result["vt_status"] = "skipped: VT_API_KEY environment variable not configured"
        return vt_result

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=6.0)
        if response.status_code == 401:
            vt_result["vt_status"] = "unauthorized: Invalid VT_API_KEY"
            return vt_result
        if response.status_code == 404:
            vt_result["vt_status"] = "not_found: IP not indexed in VirusTotal"
            return vt_result
        if response.status_code == 429:
            vt_result["vt_status"] = "rate_limited: VirusTotal API quota exceeded"
            return vt_result

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        last_date = attributes.get("last_analysis_date", "N/A")

        vt_result["vt_malicious_detections"] = stats.get("malicious", 0)
        vt_result["vt_harmless_count"] = stats.get("harmless", 0)
        vt_result["vt_last_analysis_date"] = str(last_date)
        vt_result["vt_status"] = "success"

    except requests.exceptions.RequestException as e:
        vt_result["vt_status"] = f"http_error: {str(e)}"
    except json.JSONDecodeError:
        vt_result["vt_status"] = "json_parse_error"

    return vt_result


def main():
    parser = argparse.ArgumentParser(description="Log Parser with Threat Intelligence Enrichment")
    parser.add_argument("logfile", help="Path to plain-text log file (syslog or firewall format)")
    parser.add_argument("--skip-vt", action="store_true", help="Skip VirusTotal v3 queries")
    args = parser.parse_args()

    vt_api_key = os.getenv("VT_API_KEY")

    print(f"[*] Parsing log file: {args.logfile}")
    extracted_ips = extract_public_ips(args.logfile)
    print(f"[*] Discovered {len(extracted_ips)} unique public IPv4 address(es) (private ranges excluded).")

    enriched_results: Dict[str, Dict[str, Any]] = {}

    for ip in sorted(extracted_ips):
        print(f"[*] Enriching {ip} via ip-api.com...", end=" ", flush=True)
        ip_api_data = query_ip_api(ip)
        print("Done.", end=" ")

        if not args.skip_vt:
            print("Querying VirusTotal...", end=" ", flush=True)
            vt_data = query_virustotal(ip, vt_api_key)
            print("Done.")
        else:
            vt_data = {"vt_status": "skipped_by_user"}
            print("[VT Skipped]")

        enriched_results[ip] = {
            "network_intelligence": ip_api_data,
            "threat_intelligence": vt_data
        }

    print("\n" + "=" * 70)
    print("ENRICHED LOG INTELLIGENCE REPORT (JSON)")
    print("=" * 70)
    print(json.dumps(enriched_results, indent=2))


if __name__ == "__main__":
    main()
