import os
import json
import requests
import yaml
import time
import sqlite3
import re
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = "slavengr713327-a11y"
REPO_NAME = "Watch"
DATA_PATH = "data"
DB_PATH = "vulnerability.db"

HEADERS = {
    "Accept": "application/vnd.github.v3+json",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id TEXT PRIMARY KEY,
            title TEXT,
            cve TEXT,
            severity TEXT,
            publish_date TEXT,
            year INTEGER,
            vuln_type TEXT,
            description TEXT,
            solution TEXT,
            references_json TEXT,
            cvss TEXT,
            sha TEXT,
            last_updated TEXT
        )
    ''')
    
    # 检查并修复缺失的 sha 列 (针对旧数据库)
    cursor.execute("PRAGMA table_info(vulnerabilities)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'sha' not in columns:
        print("Migrating database: adding 'sha' column...")
        cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN sha TEXT")
        
    conn.commit()
    conn.close()

def get_existing_sha(vuln_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT sha FROM vulnerabilities WHERE id = ?', (vuln_id,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def upsert_vulnerability(vuln):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Extract year from publish_date
    try:
        year = int(vuln['publish_date'].split('-')[0])
    except:
        year = datetime.now().year

    # Simple type classification based on title/description
    vuln_type = "Other"
    content_to_check = (vuln['title'] + " " + (vuln.get('description') or "")).lower()
    types_map = {
        "Injection": ["injection", "sql", "sqli", "xss", "cross-site"],
        "RCE": ["rce", "execution", "remote code"],
        "Auth": ["auth", "login", "permission", "privilege"],
        "Information Leak": ["leak", "disclosure", "sensitive"],
        "DoS": ["dos", "denial", "overflow"]
    }
    for t, keywords in types_map.items():
        if any(k in content_to_check for k in keywords):
            vuln_type = t
            break

    cursor.execute('''
        INSERT INTO vulnerabilities (
            id, title, cve, severity, publish_date, year, vuln_type, 
            description, solution, references_json, cvss, sha, last_updated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            title=excluded.title,
            cve=excluded.cve,
            severity=excluded.severity,
            publish_date=excluded.publish_date,
            year=excluded.year,
            vuln_type=excluded.vuln_type,
            description=excluded.description,
            solution=excluded.solution,
            references_json=excluded.references_json,
            cvss=excluded.cvss,
            sha=excluded.sha,
            last_updated=excluded.last_updated
    ''', (
        vuln['id'], vuln['title'], vuln['cve'], vuln['severity'], 
        vuln['publish_date'], year, vuln_type, vuln['description'], 
        vuln['solution'], json.dumps(vuln['references']), vuln['cvss'],
        vuln['sha'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()
    print(f"Successfully updated/inserted: {vuln['id']}")

def fetch_github_api(url, retries=3):
    for i in range(retries):
        try:
            response = requests.get(url, headers=HEADERS)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                wait_time = (2 ** i) + 5
                print(f"Rate limited. Waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                print(f"Error fetching {url}: {response.status_code} - {response.text}")
                break
        except Exception as e:
            print(f"Exception fetching {url}: {e}")
            time.sleep(2)
    return None

def get_file_content(download_url):
    try:
        response = requests.get(download_url)
        if response.status_code == 200:
            return response.text
    except Exception as e:
        print(f"Error downloading file: {e}")
    return None

def parse_vulnerability(content, filename):
    data = {}
    ext = os.path.splitext(filename)[1].lower()
    
    try:
        if ext == '.json':
            data = json.loads(content)
        elif ext in ['.yaml', '.yml']:
            data = yaml.safe_load(content)
        elif ext == '.md':
            lines = content.split('\n')
            title = filename
            cve = "N/A"
            if 'CVE-' in filename.upper():
                match = re.search(r'CVE-\d{4}-\d+', filename, re.IGNORECASE)
                if match:
                    cve = match.group(0).upper()
                    title = cve
            if lines and lines[0].startswith('# '):
                title = lines[0][2:].strip()
            data = {
                "title": title,
                "cve": cve,
                "description": content
            }
        
        vuln = {
            "id": data.get("id") or data.get("cve") or filename,
            "title": data.get("title") or data.get("name") or "Unknown Title",
            "cve": data.get("cve") or "N/A",
            "severity": data.get("severity") or data.get("risk_level") or "Unknown",
            "publish_date": data.get("publish_date") or data.get("date") or datetime.now().strftime("%Y-%m-%d"),
            "description": data.get("description") or data.get("summary") or "",
            "solution": data.get("solution") or data.get("remediation") or data.get("fix_suggestions") or "",
            "references": data.get("references") or data.get("links") or [],
            "cvss": data.get("cvss") or "N/A"
        }
        return vuln
    except Exception as e:
        print(f"Error parsing {filename}: {e}")
        return None

def sync():
    print(f"Starting sync from {REPO_OWNER}/{REPO_NAME}/{DATA_PATH}...")
    init_db()
    processed_count = 0

    def process_directory(path):
        nonlocal processed_count
        api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}"
        print(f"Fetching: {api_url}")
        contents = fetch_github_api(api_url)
        
        if contents is None:
            print(f"Warning: Failed to fetch content for {path}")
            return
        
        if not isinstance(contents, list):
            print(f"Notice: {path} is not a directory or is empty.")
            return

        print(f"Found {len(contents)} items in {path}")

        for item in contents:
            if item['type'] == 'file':
                filename = item['name']
                if filename.lower() == 'readme.md':
                    continue
                if any(filename.endswith(ext) for ext in ['.json', '.md', '.yaml', '.yml']):
                    vuln_id = item['path']
                    current_sha = item['sha']
                    
                    # 增量检查：对比 SHA
                    existing_sha = get_existing_sha(vuln_id)
                    if existing_sha == current_sha:
                        print(f"Skipping {vuln_id} (No changes)")
                        continue

                    print(f"Processing {vuln_id}...")
                    content = get_file_content(item['download_url'])
                    if content:
                        vuln = parse_vulnerability(content, filename)
                        if vuln:
                            vuln['id'] = vuln_id
                            vuln['sha'] = current_sha
                            upsert_vulnerability(vuln) # 搜到一个添加一个
                            processed_count += 1
            elif item['type'] == 'dir':
                if item['name'] in ['.github', 'scripts']:
                    continue
                process_directory(item['path'])

    process_directory(DATA_PATH)
    
    # 导出静态 JSON 供 GitHub Pages 使用
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vulnerabilities ORDER BY publish_date DESC')
    rows = cursor.fetchall()
    vulnerabilities = [dict(row) for row in rows]
    conn.close()

    os.makedirs("web", exist_ok=True)
    with open("web/vulnerabilities.json", "w", encoding="utf-8") as f:
        json.dump({
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "data": vulnerabilities
        }, f, indent=2, ensure_ascii=False)

    print(f"Sync complete. {processed_count} vulnerabilities processed. Static JSON exported.")

if __name__ == "__main__":
    sync()
