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

# 使用绝对路径确保与 Flask 一致
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "vulnerability.db")

HEADERS = {
    "Accept": "application/vnd.github.v3+json",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
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
        
        # 数据库迁移逻辑
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'sha' not in columns:
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN sha TEXT")
        conn.commit()

def get_existing_sha(vuln_id):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT sha FROM vulnerabilities WHERE id = ?', (vuln_id,))
        row = cursor.fetchone()
        return row[0] if row else None

def upsert_vulnerability(vuln):
    # 核心去重逻辑：优先使用 CVE，无 CVE 使用文件路径
    unique_id = vuln['cve'] if (vuln['cve'] and vuln['cve'] != 'N/A') else vuln['id']
    
    # 严格年份分类逻辑
    year = 0
    if vuln['cve'] and vuln['cve'] != 'N/A':
        match = re.search(r'CVE-(\d{4})-', vuln['cve'])
        if match:
            year = int(match.group(1))

    # 智能类型提取
    vuln_type = "Other"
    description = vuln.get('description') or ""
    # 匹配 "漏洞类型：xxx" 或 "Type: xxx" 等
    type_match = re.search(r'(?:漏洞类型|Type)[:：]\s*([^\n\r]+)', description, re.I)
    if type_match:
        vuln_type = type_match.group(1).strip()
    else:
        content_to_check = (vuln['title'] + " " + description).lower()
        types_map = {
            "Injection": ["injection", "sql", "sqli", "xss", "cross-site"],
            "RCE": ["rce", "execution", "remote code", "deserialization"],
            "Auth": ["auth", "login", "permission", "privilege", "bypass"],
            "Leak": ["leak", "disclosure", "sensitive", "exposure"],
            "DoS": ["dos", "denial", "overflow"],
            "Logic": ["logic", "workflow"],
            "Config": ["config", "misconfiguration"]
        }
        for t, keywords in types_map.items():
            if any(k in content_to_check for k in keywords):
                vuln_type = t
                break

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
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
            unique_id, vuln['title'], vuln['cve'], vuln['severity'], 
            vuln['publish_date'], year, vuln_type, vuln['description'], 
            vuln['solution'], json.dumps(vuln.get('references', [])), vuln['cvss'],
            vuln['sha'], datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
    print(f"Successfully synced: {unique_id} ({year})")

def fetch_github_api(url, retries=3):
    for i in range(retries):
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                wait_time = (2 ** i) + 5
                time.sleep(wait_time)
            else:
                break
        except:
            time.sleep(2)
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
                if match: cve = match.group(0).upper()
            if lines and lines[0].startswith('# '):
                title = lines[0][2:].strip()
            data = {"title": title, "cve": cve, "description": content}
        
        return {
            "id": data.get("id") or data.get("cve") or filename,
            "title": data.get("title") or data.get("name") or "Unknown",
            "cve": data.get("cve") or "N/A",
            "severity": data.get("severity") or data.get("risk_level") or "Unknown",
            "publish_date": data.get("publish_date") or data.get("date") or datetime.now().strftime("%Y-%m-%d"),
            "description": data.get("description") or data.get("summary") or "",
            "solution": data.get("solution") or data.get("fix") or "",
            "references": data.get("references") or [],
            "cvss": str(data.get("cvss") or "N/A"),
            "sha": ""
        }
    except:
        return None

def sync():
    init_db()
    processed_count = 0

    def process_directory(path):
        nonlocal processed_count
        api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}"
        contents = fetch_github_api(api_url)
        if not contents or not isinstance(contents, list): return

        for item in contents:
            if item['type'] == 'file':
                filename = item['name']
                if filename.lower() == 'readme.md' or not any(filename.endswith(ext) for ext in ['.json', '.md', '.yaml', '.yml']):
                    continue
                
                vuln_id = item['path']
                current_sha = item['sha']
                if get_existing_sha(vuln_id) == current_sha:
                    continue

                content = requests.get(item['download_url']).text
                vuln = parse_vulnerability(content, filename)
                if vuln:
                    vuln['id'] = vuln_id
                    vuln['sha'] = current_sha
                    upsert_vulnerability(vuln)
                    processed_count += 1
            elif item['type'] == 'dir' and item['name'] not in ['.github', 'scripts']:
                process_directory(item['path'])

    process_directory(DATA_PATH)
    
    # 导出静态 JSON (保持兼容)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        vulnerabilities = [dict(row) for row in conn.execute('SELECT * FROM vulnerabilities ORDER BY publish_date DESC').fetchall()]
        os.makedirs("web", exist_ok=True)
        with open("web/vulnerabilities.json", "w", encoding="utf-8") as f:
            json.dump({"last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "data": vulnerabilities}, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    sync()
