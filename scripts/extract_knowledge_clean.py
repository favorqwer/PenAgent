import os
import re
import shutil
from pathlib import Path
import yaml

RAW_DIR = Path(r"C:\Users\Favor\Desktop\PenAgent\data\knowledge_raw")
CLEAN_DIR = Path(r"C:\Users\Favor\Desktop\PenAgent\data\knowledge_clean")

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# -------------------------------------------------------------
# 1. HackTricks: Network Services, Linux Privesc, Web Methodologies
# -------------------------------------------------------------
def extract_hacktricks():
    src_base = RAW_DIR / "HackTricks" / "src"
    dst_base = CLEAN_DIR / "01_hacktricks_attack_chains"
    ensure_dir(dst_base)
    
    target_subdirs = [
        "network-services-pentesting",
        "linux-hardening/privilege-escalation",
        "pentesting-web"
    ]
    
    count = 0
    for rel_sub in target_subdirs:
        sub_path = src_base / rel_sub
        if not sub_path.exists():
            continue
        for md_file in sub_path.rglob("*.md"):
            # skip non-markdown and readmes that are just index lists
            try:
                rel = md_file.relative_to(src_base)
                # flatten path to a clean readable filename
                safe_name = str(rel).replace("\\", "__").replace("/", "__")
                content = md_file.read_text(encoding="utf-8", errors="replace")
                
                # strip image links to save token space
                cleaned = re.sub(r'!\[.*?\]\(.*?\)', '', content)
                # write out
                (dst_base / safe_name).write_text(cleaned, encoding="utf-8")
                count += 1
            except Exception as e:
                pass
    print(f"[1/6] HackTricks extracted: {count} attack chain files.")

# -------------------------------------------------------------
# 2. GTFOBins: Linux SUID / Sudo PrivEsc paths
# -------------------------------------------------------------
def extract_gtfobins():
    src_base = RAW_DIR / "GTFOBins" / "_gtfobins"
    dst_base = CLEAN_DIR / "02_gtfobins_privesc"
    ensure_dir(dst_base)
    
    count = 0
    if src_base.exists():
        for bin_file in src_base.iterdir():
            if bin_file.is_file():
                try:
                    content = bin_file.read_text(encoding="utf-8", errors="replace")
                    (dst_base / f"{bin_file.name}.md").write_text(content, encoding="utf-8")
                    count += 1
                except Exception:
                    pass
    print(f"[2/6] GTFOBins extracted: {count} privesc binary files.")

# -------------------------------------------------------------
# 3. Vulhub: End-to-end CVE Exploit Chains & Writeups
# -------------------------------------------------------------
def extract_vulhub():
    src_base = RAW_DIR / "vulhub"
    dst_base = CLEAN_DIR / "03_vulhub_exploit_chains"
    ensure_dir(dst_base)
    
    count = 0
    if src_base.exists():
        for readme in src_base.rglob("README.md"):
            try:
                rel = readme.relative_to(src_base)
                parts = rel.parts
                if len(parts) >= 2:
                    # component is parts[0], cve/app is parts[1]
                    component = parts[0]
                    vuln_name = "__".join(parts[1:-1]) if len(parts) > 2 else parts[1]
                    out_name = f"{component}__{vuln_name}.md" if vuln_name != "README.md" else f"{component}.md"
                else:
                    out_name = f"{parts[0]}.md"
                
                content = readme.read_text(encoding="utf-8", errors="replace")
                if len(content.strip()) < 100:
                    continue  # skip empty or stub readmes
                
                # Strip useless docker-compose commands if purely local, but keep vulnerability description and exploit commands
                cleaned = re.sub(r'!\[.*?\]\(.*?\)', '', content)
                (dst_base / out_name).write_text(cleaned, encoding="utf-8")
                count += 1
            except Exception:
                pass
    print(f"[3/6] Vulhub extracted: {count} exploit chain writeups.")

# -------------------------------------------------------------
# 4. Nuclei Templates: High/Critical CVE Threat Catalog
# -------------------------------------------------------------
def extract_nuclei():
    src_dirs = [
        RAW_DIR / "nuclei-templates" / "http" / "cves",
        RAW_DIR / "nuclei-templates" / "network" / "cves"
    ]
    dst_base = CLEAN_DIR / "04_cve_threat_catalog"
    ensure_dir(dst_base)
    
    count = 0
    for sdir in src_dirs:
        if not sdir.exists():
            continue
        for yfile in sdir.rglob("*.yaml"):
            try:
                with open(yfile, "r", encoding="utf-8", errors="replace") as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                info = data.get("info", {})
                severity = str(info.get("severity", "")).lower()
                if severity not in ("critical", "high"):
                    continue
                
                cve_id = data.get("id") or yfile.stem
                name = info.get("name", "Unknown Vulnerability")
                desc = info.get("description", "No description")
                tags = info.get("tags", "")
                
                # Extract exploit request highlights
                requests_info = []
                for http in data.get("http", []) or []:
                    method = http.get("method", "GET")
                    raw_paths = http.get("path", [])
                    requests_info.append(f"HTTP Method: {method}, Target Paths: {raw_paths[:2]}")
                for net in data.get("network", []) or []:
                    inputs = net.get("inputs", [])
                    requests_info.append(f"Network payload: {inputs[:1]}")
                
                md_content = f"""# {cve_id}: {name}
- **Severity**: {severity.upper()}
- **Tags / Software**: {tags}
- **Description**: {desc}
- **Exploitation Vector**:
{chr(10).join('- ' + req for req in requests_info) if requests_info else 'N/A'}
"""
                (dst_base / f"{cve_id}.md").write_text(md_content, encoding="utf-8")
                count += 1
            except Exception:
                pass
    print(f"[4/6] Nuclei extracted: {count} High/Critical CVE threat cards.")

# -------------------------------------------------------------
# 5. PayloadsAllTheThings: Methodology and Attack Escalation
# -------------------------------------------------------------
def extract_payloads():
    src_base = RAW_DIR / "PayloadsAllTheThings"
    dst_base = CLEAN_DIR / "05_payload_methodologies"
    ensure_dir(dst_base)
    
    count = 0
    if src_base.exists():
        for readme in src_base.rglob("*.md"):
            try:
                # Only keep main category READMEs or Methodology docs, skip non-essential sub-folders
                rel = readme.relative_to(src_base)
                rel_str = str(rel)
                if "Methodology" in rel_str or readme.name == "README.md":
                    clean_name = rel_str.replace("\\", "__").replace("/", "__")
                    content = readme.read_text(encoding="utf-8", errors="replace")
                    if len(content.strip()) > 200:
                        (dst_base / clean_name).write_text(content, encoding="utf-8")
                        count += 1
            except Exception:
                pass
    print(f"[5/6] PayloadsAllTheThings extracted: {count} methodology documents.")

# -------------------------------------------------------------
# 6. SecLists: Common Server & Middleware Default Credentials
# -------------------------------------------------------------
def extract_credentials():
    src_base = RAW_DIR / "SecLists-DefaultCredentials" / "Passwords" / "Default-Credentials"
    dst_base = CLEAN_DIR / "06_middleware_default_creds"
    ensure_dir(dst_base)
    
    keywords = ["tomcat", "weblogic", "jenkins", "mysql", "postgres", "redis", "ssh", "ftp", "vnc", "oracle", "jboss"]
    count = 0
    if src_base.exists():
        for txt in src_base.glob("*.txt"):
            stem = txt.stem.lower()
            if any(k in stem for k in keywords):
                try:
                    content = txt.read_text(encoding="utf-8", errors="replace")
                    # Convert into markdown list format
                    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
                    md_text = f"# Default Credentials for {txt.stem}\n\n"
                    md_text += "\n".join(f"- `{line}`" for line in lines[:80]) # keep top 80 common pairs
                    (dst_base / f"{txt.stem}.md").write_text(md_text, encoding="utf-8")
                    count += 1
                except Exception:
                    pass
    print(f"[6/6] Default Credentials extracted: {count} server credential profiles.")

def main():
    print(f"Extracting high-value attack knowledge into: {CLEAN_DIR}")
    ensure_dir(CLEAN_DIR)
    extract_hacktricks()
    extract_gtfobins()
    extract_vulhub()
    extract_nuclei()
    extract_payloads()
    extract_credentials()
    print("All extractions completed successfully!")

if __name__ == "__main__":
    main()
