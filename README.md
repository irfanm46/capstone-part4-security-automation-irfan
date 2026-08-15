# Python Security Automation & AI/ML-Driven Threat Detection

**Course Module:** Security Automation & Machine Learning for Threat Detection  
**Author:** Irfan Musthafa  
**Repository:** `capstone-part4-security-automation-irfan`

---

## 1. Project Overview & Architecture

This repository delivers three core cybersecurity automation tools designed to minimize Security Operations Center (SOC) manual workload through automated network reconnaissance, log enrichment, and machine-learning threat classification:

1. **`port_scanner.py`**: A pure-Python multithreaded TCP port scanner with dynamic banner grabbing and thread-safe data synchronization.
2. **`log_enricher.py`**: An automated log parsing and threat intelligence enrichment pipeline that extracts public IPv4 addresses, filters RFC 1918 private subnets, queries `ip-api.com` for geolocation/ISP data, and enriches indicators via VirusTotal API v3.
3. **`threat_detector.py`**: An AI/ML pipeline training a supervised Random Forest Classifier and an unsupervised Isolation Forest anomaly detector on a 6,000-sample security dataset.

---

## 2. Input → Process → Output Automation Mindset

The Input → Process → Output (IPO) architecture is a software design pattern where data ingestion, business/analytical logic, and presentation are strictly decoupled. This modularity ensures security automation scripts can be chained into continuous orchestration pipelines without manual human glue code.

```
+-----------------------------------------------------------------------------------+
|                        INPUT -> PROCESS -> OUTPUT MAPPING                         |
+-------------------+------------------------------+--------------------------------+
| Script            | Input Stage                  | Process Stage                  |
+-------------------+------------------------------+--------------------------------+
| port_scanner.py   | Target IP & port range args  | Multithreaded TCP 3-way        |
|                   | via CLI                      | handshake & banner probe       |
+-------------------+------------------------------+--------------------------------+
| log_enricher.py   | Plaintext auth/firewall logs | Regex extraction, private      |
|                   | & VT_API_KEY env var         | IP filtering, REST API queries |
+-------------------+------------------------------+--------------------------------+
| threat_detector.py| 6,000-sample security        | 80/20 train-test split, RF     |
|                   | feature CSV dataset          | & Isolation Forest fitting     |
+-------------------+------------------------------+--------------------------------+
```

* **`port_scanner.py`**:
  * **Input:** Target IP/hostname, port range (`1-1024`), timeout (`1.0s`), and concurrency limits via `argparse`.
  * **Process:** Concurrent worker threads executing non-blocking TCP handshakes and banner grabbing with `threading.Lock` synchronization.
  * **Output:** A formatted terminal summary table mapping `Port | State | Banner`.
* **`log_enricher.py`**:
  * **Input:** Unstructured plaintext syslog/firewall logs and `VT_API_KEY` from environment variables.
  * **Process:** Regex-based IPv4 pattern matching, RFC 1918 private subnet exclusion, deduplication via Python sets, and REST API querying against `ip-api.com` and VirusTotal API v3.
  * **Output:** A structured JSON object containing geolocation, hosting/proxy status, and vendor threat detection counts.
* **`threat_detector.py`**:
  * **Input:** 6,000-record CSV dataset with 15 numerical cybersecurity features and binary threat labels.
  * **Process:** Deduplication, missing-value imputation, stratified 80/20 train/test splitting, Random Forest classification, and Isolation Forest contamination modeling.
  * **Output:** Scikit-learn classification reports, precision/recall/F1 metrics, and model comparison matrices.

---

## 3. Multithreaded Port Scanner (`port_scanner.py`)

### Usage
```bash
python port_scanner.py scanme.nmap.org -p 20-100 -t 1.0 --max-threads 50
```

### Sample Output
```text
======================================================================
[*] Target IP Address : 45.33.32.156 (scanme.nmap.org)
[*] Scanning Ports    : 20 to 100
[*] Timeout per Port  : 1.0s
[*] Concurrency Limit : 50 threads
======================================================================

======================================================================
Port       | State      | Banner
----------------------------------------------------------------------
22         | OPEN       | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80         | OPEN       | HTTP/1.1 400 Bad Request
======================================================================
[*] Scan complete. Found 2 open port(s).
```

---

## 4. Log Parsing & Threat Intelligence Enrichment (`log_enricher.py`)

### Usage
```bash
# Run log enrichment across ip-api.com and VirusTotal API v3
python log_enricher.py sample_auth.log
```

### Sample Enriched JSON Output (Tasks 2 & 4)
```json
{
  "1.1.1.1": {
    "network_intelligence": {
      "country": "Australia",
      "isp": "Cloudflare, Inc.",
      "is_hosting": true,
      "is_proxy": false,
      "is_mobile": false,
      "api_status": "success"
    },
    "threat_intelligence": {
      "vt_malicious_detections": 0,
      "vt_harmless_count": 89,
      "vt_last_analysis_date": "1715678400",
      "vt_status": "success"
    }
  },
  "45.33.32.156": {
    "network_intelligence": {
      "country": "United States",
      "isp": "Linode, LLC",
      "is_hosting": true,
      "is_proxy": false,
      "is_mobile": false,
      "api_status": "success"
    },
    "threat_intelligence": {
      "vt_malicious_detections": 1,
      "vt_harmless_count": 82,
      "vt_last_analysis_date": "1715678120",
      "vt_status": "success"
    }
