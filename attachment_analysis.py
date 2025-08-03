import os
import re
import email
import requests
import time
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

# === CONFIGURATION ===
SAVE_DIR = "attachments"
VT_API_KEY = "5cdd731ffe102ac14c823178e67cddfddfdca2f92d65c489de9e8f276a19cc27"
CUSTOM_URL_SCAN_API = "http://127.0.0.1:8002/predict/url"

# === HELPERS ===

def extract_attachments_and_urls(eml_path, save_dir=SAVE_DIR):
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            file_path = os.path.join(save_dir, filename)
            with open(file_path, 'wb') as af:
                af.write(part.get_payload(decode=True))
            attachments.append(file_path)

    # Extract body and URLs
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        body = msg.get_content()

    urls = re.findall(r'https?://[^\s<>\"]+', body)
    return attachments, urls

def scan_file_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': VT_API_KEY}

    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        analysis_url = response.json()['data']['id']
        return poll_virustotal_analysis(analysis_url)
    else:
        return f"Upload failed: {response.status_code} - {response.text}"

def poll_virustotal_analysis(analysis_id):
    headers = {'x-apikey': VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for _ in range(10):
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data['data']['attributes']['status']
            if status == 'completed':
                stats = data['data']['attributes']['stats']
                return f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Harmless: {stats['harmless']}"
            else:
                time.sleep(2)
        else:
            return f"Error: {response.status_code} - {response.text}"
    return "Timeout waiting for analysis"

def scan_url_custom(url):
    print(f"🔍 Checking URL with custom API: {url}")
    try:
        response = requests.post(CUSTOM_URL_SCAN_API, json={"url": url})
        if response.status_code == 200:
            result = response.json()
            return f"Result: {result}"
        else:
            return f"Error: {response.status_code} {response.text}"
    except Exception as e:
        return f"Exception occurred: {e}"

def is_obfuscated_url(url):
    suspicious_shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly']
    domain = urlparse(url).netloc
    return any(short in domain for short in suspicious_shorteners)

# === MAIN SCANNER FUNCTION ===

def scan_email(eml_path):
    print(f"\n📂 Scanning: {eml_path}")
    attachments, urls = extract_attachments_and_urls(eml_path)

    print("\n📎 Attachments found:")
    for file in attachments:
        result = scan_file_virustotal(file)
        print(f" - {file} → {result}")

    print("\n🔗 URLs found:")
    for url in urls:
        obf = "Yes" if is_obfuscated_url(url) else "No"
        custom_result = scan_url_custom(url)
        print(f"\n- {url}")
        print(f"  Obfuscated: {obf}")
        print(f"  Custom API: {custom_result}")

# === CLI ENTRY POINT ===

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python attachment_link_scanner.py path/to/email.eml")
        exit(1)

    scan_email(sys.argv[1])
