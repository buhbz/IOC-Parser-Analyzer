# IOC-Parser-Analyzer
A Python tool that extracts security indicators and saves them into organized text files. It can also scan log files and automatically check found hashes against the VirusTotal API to pull threat summaries.

## Features

* **PDF Parsing**: Automatically scans all PDFs in the current directory and pulls out common security indicators.
* **Organized Storage**: Groups found indicators by type (IPs, URLs, Hashes, CVEs, etc.) and saves them into separate text files inside an `ioc/` folder.
* **Smart Duplication Checks**: Uses in-memory tracking to ensure indicators are not saved multiple times, speeding up the script.
* **VirusTotal Integration**: Queries the VirusTotal API for file hashes to pull threat labels and suspicious keywords.
* **API Rate Control**: Automatically stops making API calls if you hit your VirusTotal rate limit.

## What It Finds

* MD5 and SHA256 Hashes
* IPv4 Addresses
* Domains and URLs
* Email Addresses
* CVE Vulnerabilities
* Windows Registry Paths and CLSIDs
* Local Windows File Paths

## Prerequisites

You need Python 3 installed along with a few external libraries. You will also need a VirusTotal API key if you want to use the analysis feature.

Install the required packages using pip:

```bash
pip install pypdf requests
```

## Setup
1. Clone this repository to your local machine.
2. Open the script file and locate the `apiKEY` variable at the top:
   ```python
   apiKEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
   ```
3. Replace the placeholder string with your actual VirusTotal API key.
   
## Usage

The script requires you to pass one of two flags depending on what you want to do.

### 1. Parsing PDFs
To scan all PDF files in your current working directory for indicators:

```bash
python iocParseAnalysis.py -p
```

### 2. Analyzing a Log File
To scan a specific text log file and run its hashes through VirusTotal:

```bash
python iocParseAnalysis.py -a path/to/your/logfile.txt
```
The console will print out how many security vendors flagged the file as malicious, the threat type, and the top suspicious keywords associated with the hash.

