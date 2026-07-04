import re
from pypdf import PdfReader
import sys
import argparse
import requests
import json
from pathlib import Path

apiKEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
vtURL = "https://www.virustotal.com/api/v3/files/{}"

parser = argparse.ArgumentParser(description='IOC parsing & analysis. One argument must be passed, parse file, or analysis file.')
parser.add_argument('-p', '--parse', action = 'store_true', help='parse every pdf in py file root')
parser.add_argument('-a', '--analysis', type=str, help='filename || path to file for analysis')
args = parser.parse_args()

def queryVT(fileHash):
    headers = {"x-apikey": apiKEY}
    r = requests.get(vtURL.format(fileHash), headers=headers)

    if r.status_code in (401, 403, 429):
        print("[!] VirusTotal limit/auth block reached. Stopping VT queries. Ensure proper API key is passed.")
        return None, True

    if r.status_code != 200:
        print(f"[!] VT lookup failed for {fileHash}: HTTP {r.status_code}")
        return None, False

    return r.json(), False


def extractKW(jsonText):
    keywords = set()

    patterns = [
        r'"suggested_threat_label"\s*:\s*"([^"]+)"',
        r'"value"\s*:\s*"([^"]+)"',
        r'"result"\s*:\s*"([^"]+)"',
        r'"rule_name"\s*:\s*"([^"]+)"',
        r'"description"\s*:\s*"([^"]+)"',
        r'"malware_classification"\s*:\s*\[\s*"([^"]+)"',
        r'"malware_names"\s*:\s*\[\s*"([^"]+)"',
    ]

    for pattern in patterns:
        for match in re.findall(pattern, jsonText, re.I):
            keywords.add(match)

    return sorted(keywords)

def jsonSummary(jsonText):
    malicious = re.search(r'"malicious"\s*:\s*(\d+)', jsonText)
    undetected = re.search(r'"undetected"\s*:\s*(\d+)', jsonText)
    label = re.search(r'"suggested_threat_label"\s*:\s*"([^"]+)"', jsonText)
    file_type = re.search(r'"type_description"\s*:\s*"([^"]+)"', jsonText)

    parts = []

    if malicious:
        parts.append(f"{malicious.group(1)} providers flagged it malicious")

    if undetected:
        parts.append(f"{undetected.group(1)} did not detect it")

    if label:
        parts.append(f"possible threat: {label.group(1)}")

    if file_type:
        parts.append(f"file type: {file_type.group(1)}")

    return "; ".join(parts) if parts else "No clear VirusTotal summary found."

def saveFinds(matches, storage):
    temp = []
    with open(storage, 'r') as f:
        line = 'y'
        while line != '':
            if line[0] != '-' and line[0] != '':
                temp.append(line)
            line = f.readline()

    with open(storage, 'a') as f:

        for match in matches:
            if match not in temp:
                f.write('\n'+match)


iocConfigs = {
    'md5': {
        'label': 'MD5 Hashes',
        'pattern': re.compile(r"[a-fA-F0-9]{32}"),
        'storage': 'ioc/MD5HASHES.txt'
    },
    'clsid': {
        'label': 'CLSID Hashes',
        'pattern': re.compile(r"[a-fA-F0-9]{8}\s*-\s*[a-fA-F0-9]{4}\s*-\s*[a-fA-F0-9]{4}\s*-\s*[a-fA-F0-9]{4}\s*-\s*[a-fA-F0-9]{12}"),
        'storage': 'ioc/CLSID.txt'
    },
    'path': {
        'label': 'Paths',
        'pattern': re.compile(r"[a-zA-Z]:\\[^\s?|\"<>*]+"),
        'storage': 'ioc/PATHS.txt'
    },
    'sha256': {
        'label': 'SHA256 Hashes',
        'pattern': re.compile(r"\b[a-fA-F0-9]{64}\b"),
        'storage': 'ioc/SHA256HASHES.txt'
    },
    'ipv4': {
        'label': 'IPv4 Addresses',
        'pattern': re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        'storage': 'ioc/IPV4.txt'
    },
    'domain': {
        'label': 'Domains',
        'pattern': re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b"),
        'storage': 'ioc/DOMAINS.txt'
    },
    'url': {
        'label': 'URLs',
        'pattern': re.compile(r"https?://[^\s\"'<>]+"),
        'storage': 'ioc/URLS.txt'
    },
    'email': {
        'label': 'Email Addresses',
        'pattern': re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
        'storage': 'ioc/EMAILS.txt'
    },
    'cve': {
        'label': 'CVE Vulnerabilities',
        'pattern': re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
        'storage': 'ioc/CVES.txt'
    },
    'registry_path': {
        'label': 'Registry Paths',
        'pattern': re.compile(r"\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"<>*]+", re.IGNORECASE),
        'storage': 'ioc/REGISTRYPATHS.txt'
    }
}

if not args.parse and not args.analysis:
    print("Must be run with either --parse or --analysis. EX: py iocParseAnalysis.py -p || py iocParseAnalysis.py -a ioc.txt")
    sys.exit(1)

if args.parse:

    dirPath = Path.cwd()
    print(f"Scanning {dirPath}...")
    files = [item for item in dirPath.iterdir() if item.is_file() and item.suffix == '.pdf']
    skippedFiles = []

    if len(files) == 0:
        print("No PDF files found. Exiting.")
        sys.exit(1)

    for file in files:
        try:
            pdf = PdfReader(file)
            for iocName, iocConfig in iocConfigs.items():
                with open(iocConfig['storage'], 'a') as f:
                    f.write(f'\n-----{file.name}-----')
        except:
            print(f"Error parsing {file}, possible corruption. Skipping file.")
            skippedFiles.append(file)
            continue

        print(f"PARSING FILE: {file.name}")
        for page in pdf.pages:
            text = page.extract_text()

            for iocName, iocConfig in iocConfigs.items():
                saveFinds(iocConfig['pattern'].findall(text), iocConfig['storage'])

        pdf.close()

    for file in skippedFiles:
        files.remove(file)
    print(f"PARSED {len(files)} PDF files.")

if args.analysis:
    with open ('iocLog.txt','r') as log:
        file = log.read()
        skippedVulns = []
        scannedVulns = 0
        stopVT = False

        for iocName, iocConfig in iocConfigs.items():
            matches = iocConfig['pattern'].findall(file)

            for vuln in matches:

                if stopVT:
                    skippedVulns.append(vuln)
                    continue

                if iocName not in ["md5", "sha256"]:
                    skippedVulns.append(vuln)
                    continue

                vtResult, stopVT = queryVT(vuln)
                if vtResult is None:
                    continue

                scannedVulns+=1
                print(f"\n****Potential IOC: {vuln}****")
                report = json.dumps(vtResult)
                print(jsonSummary(report))

                KW = extractKW(json.dumps(vtResult))
                if KW:
                    print("suspicious Keywords: ")
                    for kw in KW[:10]:
                        print(f"- {kw}")

    print(f"\n----Found {len(skippedVulns)+scannedVulns} IOC's. These could not be scanned:----\n")
    for vuln in skippedVulns:
        print(vuln)
    print(f"----Found {len(skippedVulns)+scannedVulns} IOC's. These could not be scanned----")





