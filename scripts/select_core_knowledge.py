import argparse
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLEAN_DIR = PROJECT_ROOT / "data" / "knowledge_clean"
CORE_DIR = PROJECT_ROOT / "data" / "knowledge_core"
LOOKUP_DIR = PROJECT_ROOT / "data" / "knowledge_lookup"

HACKTRICKS_DIR = CLEAN_DIR / "01_hacktricks_attack_chains"
GTFOBINS_DIR = CLEAN_DIR / "02_gtfobins_privesc"
VULHUB_DIR = CLEAN_DIR / "03_vulhub_exploit_chains"
PAYLOAD_DIR = CLEAN_DIR / "05_payload_methodologies"
CREDS_DIR = CLEAN_DIR / "06_middleware_default_creds"

# Tier 1: target-agnostic network services.
HACKTRICKS_SERVICES: List[str] = [
    "network-services-pentesting__pentesting-ssh.md",
    "network-services-pentesting__pentesting-ftp__README.md",
    "network-services-pentesting__pentesting-smb__README.md",
    "network-services-pentesting__pentesting-mysql.md",
    "network-services-pentesting__pentesting-mssql-microsoft-sql-server__README.md",
    "network-services-pentesting__pentesting-postgresql.md",
    "network-services-pentesting__6379-pentesting-redis.md",
    "network-services-pentesting__pentesting-rdp.md",
    "network-services-pentesting__pentesting-snmp__README.md",
    "network-services-pentesting__pentesting-ldap.md",
    "network-services-pentesting__9200-pentesting-elasticsearch.md",
    "network-services-pentesting__27017-27018-mongodb.md",
    "network-services-pentesting__pentesting-vnc.md",
    "network-services-pentesting__pentesting-telnet.md",
    "network-services-pentesting__pentesting-rpcbind.md",
    "network-services-pentesting__nfs-service-pentesting.md",
    "network-services-pentesting__2375-pentesting-docker.md",
    "network-services-pentesting__11211-memcache__README.md",
]

# Tier 1: self-contained web methodology documents.
WEB_METHODOLOGIES_CORE: List[str] = [
    "Account Takeover__README.md",
    "Brute Force Rate Limit__README.md",
    "Command Injection__README.md",
    "Directory Traversal__README.md",
    "File Inclusion__README.md",
    "JSON Web Token__README.md",
    "NoSQL Injection__README.md",
    "Server Side Request Forgery__README.md",
    "Server Side Template Injection__README.md",
    "SQL Injection__README.md",
    "Upload Insecure Files__README.md",
    "XXE Injection__README.md",
]

# Full profile: keep the index page, but skip the link-only "content moved" pages.
WEB_METHODOLOGIES_FULL: List[str] = WEB_METHODOLOGIES_CORE + [
    "Insecure Deserialization__README.md",
]

# Tier 2: representative, high-frequency middleware / CVE writeups.
# This is an explicit allowlist on purpose: re-running the script is reproducible.
MIDDLEWARE_CORE: List[str] = [
    # Tomcat
    "tomcat__CVE-2017-12615.md",
    "tomcat__CVE-2020-1938.md",
    "tomcat__CVE-2025-24813.md",
    "tomcat__tomcat8.md",
    # Spring
    "spring__CVE-2022-22965.md",
    "spring__CVE-2022-22947.md",
    "spring__CVE-2022-22963.md",
    "spring__CVE-2018-1273.md",
    "spring__CVE-2017-8046.md",
    "spring__CVE-2025-41242.md",
    # WebLogic
    "weblogic__CVE-2020-14882.md",
    "weblogic__CVE-2023-21839.md",
    "weblogic__CVE-2017-10271.md",
    "weblogic__weak_password.md",
    # Fastjson
    "fastjson__1.2.24-rce.md",
    "fastjson__1.2.47-rce.md",
    "fastjson__1.2.83-rce.md",
    # Shiro
    "shiro__CVE-2016-4437.md",
    "shiro__CVE-2020-1957.md",
    "shiro__CVE-2010-3863.md",
    # Log4j
    "log4j__CVE-2021-44228.md",
    # Confluence
    "confluence__CVE-2021-26084.md",
    "confluence__CVE-2022-26134.md",
    "confluence__CVE-2023-22527.md",
    # Jenkins
    "jenkins__CVE-2024-23897.md",
    "jenkins__CVE-2018-1000861.md",
    # Redis
    "redis__4-unacc.md",
    "redis__CVE-2022-0543.md",
    # PHP
    "php__CVE-2019-11043.md",
    "php__CVE-2012-1823.md",
    "php__fpm.md",
    "php__inclusion.md",
    "php__php_xxe.md",
    "php__8.1-backdoor.md",
    # Nginx
    "nginx__CVE-2013-4547.md",
    "nginx__CVE-2017-7529.md",
    "nginx__insecure-configuration.md",
    "nginx__nginx_parsing_vulnerability.md",
    # ThinkPHP
    "thinkphp__5-rce.md",
    "thinkphp__5.0.23-rce.md",
    "thinkphp__lang-rce.md",
    # Struts2
    "struts2__s2-045.md",
    "struts2__s2-059.md",
    "struts2__s2-061.md",
    "struts2__s2-066.md",
    "struts2__s2-067.md",
    # ActiveMQ
    "activemq__CVE-2015-5254.md",
    "activemq__CVE-2016-3088.md",
    "activemq__CVE-2023-46604.md",
    # Solr
    "solr__CVE-2017-12629-RCE.md",
    "solr__CVE-2019-0193.md",
    # GitLab
    "gitlab__CVE-2021-22205.md",
    "gitlab__CVE-2026-85706.md",
    # JBoss
    "jboss__CVE-2017-12149.md",
    "jboss__CVE-2017-7504.md",
    "jboss__JMXInvokerServlet-deserialization.md",
    # Shellshock / database CVEs
    "bash__CVE-2014-6271.md",
    "mysql__CVE-2012-2122.md",
    "postgres__CVE-2018-1058.md",
    "postgres__CVE-2019-9193.md",
]

# General high-frequency services missing from the old keyword selection.
APACHE_CORE: List[Tuple[str, str]] = [
    ("03_vulhub_exploit_chains", "httpd__CVE-2021-41773.md"),
    ("03_vulhub_exploit_chains", "httpd__CVE-2021-42013.md"),
    ("03_vulhub_exploit_chains", "httpd__CVE-2021-40438.md"),
    ("03_vulhub_exploit_chains", "httpd__CVE-2017-15715.md"),
    ("01_hacktricks_attack_chains", "network-services-pentesting__pentesting-web__apache.md"),
    ("01_hacktricks_attack_chains", "network-services-pentesting__8009-pentesting-apache-jserv-protocol-ajp.md"),
    ("01_hacktricks_attack_chains", "network-services-pentesting__pentesting-dns.md"),
]

# Curated GTFOBins set moved to lookup (the old 51-file core selection).
GTFOBINS_CORE: List[str] = [
    "bash", "dash", "sudo", "docker", "find", "vim", "vi", "nano", "less", "more",
    "cp", "mv", "sed", "python", "perl", "ruby", "php", "tar", "zip",
    "gzip", "curl", "wget", "nc", "socat", "nmap", "systemctl", "env", "tee",
    "chown", "chmod", "dd", "date", "gdb", "ssh", "scp", "git", "passwd",
    "pkexec", "apt-get", "dpkg", "rpm", "yum", "su", "flock", "lxd", "strace",
    "ltrace", "xargs", "taskset", "make", "crontab",
]

# GTFOBins kept in lookup; mark the usual first-choice binaries.
GTFOBINS_PRIORITY: List[str] = [
    "bash",
    "php",
    "python",
    "socat",
    "less",
    "tar",
    "git",
    "ruby",
    "vi",
    "perl",
    "wget",
    "curl",
    "xargs",
    "nc",
    "ssh",
    "docker",
    "cp",
    "nmap",
    "find",
    "gdb",
]

LOOKUP_README = """# Knowledge Lookup

This directory is intentionally **not** indexed into LightRAG.

- `creds/` — default credential lists, used as a deterministic wordlist.
- `gtfobins/` — GTFOBins command snippets. `manifest.json` marks the usual
  first-choice binaries with `"priority": "core"`; the rest are `"extended"`.

Keeping these out of the knowledge graph avoids polluting it with credential
strings and one-line command snippets.
"""


def _copy_doc(
    src: Path,
    dest_root: Path,
    category: str,
    tier: str,
    description: str,
    manifest: List[Dict[str, Any]],
    seen: Set[Path],
    dry_run: bool,
    extra: Dict[str, Any] | None = None,
) -> bool:
    if not src.is_file():
        print(f"[MISS] {src}")
        return False

    resolved = src.resolve()
    if resolved in seen:
        return False
    seen.add(resolved)

    dest = dest_root / category / src.name
    if not dry_run:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)

    entry: Dict[str, Any] = {
        "category": category,
        "tier": tier,
        "file_name": src.name,
        "rel_path": str(dest.relative_to(dest_root)).replace("\\", "/"),
        "size_chars": len(src.read_text(encoding="utf-8", errors="replace")),
        "description": description,
    }
    if extra:
        entry.update(extra)
    manifest.append(entry)
    return True


def _reset_dir(path: Path, dry_run: bool) -> None:
    if dry_run:
        return
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _write_manifest(path: Path, manifest: List[Dict[str, Any]], dry_run: bool) -> None:
    if dry_run:
        return
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")


def _summary(label: str, manifest: Sequence[Dict[str, Any]]) -> None:
    print("=" * 60)
    print(label)
    print("=" * 60)
    by_category: Dict[str, int] = {}
    by_tier: Dict[str, int] = {}
    for item in manifest:
        by_category[item["category"]] = by_category.get(item["category"], 0) + 1
        by_tier[item["tier"]] = by_tier.get(item["tier"], 0) + 1
    for category, count in sorted(by_category.items()):
        print(f"  {category:<28}: {count:>4}")
    print("-" * 60)
    for tier, count in sorted(by_tier.items()):
        print(f"  {tier:<28}: {count:>4}")
    print(f"  {'TOTAL':<28}: {len(manifest):>4}")


def build_core(profile: str, dry_run: bool) -> List[Dict[str, Any]]:
    _reset_dir(CORE_DIR, dry_run)
    manifest: List[Dict[str, Any]] = []
    seen: Set[Path] = set()

    for name in HACKTRICKS_SERVICES:
        _copy_doc(
            HACKTRICKS_DIR / name,
            CORE_DIR,
            "03_network_services",
            "tier1",
            f"Target-agnostic service guide for {Path(name).stem}",
            manifest,
            seen,
            dry_run,
        )

    web_docs = WEB_METHODOLOGIES_CORE if profile == "hot" else WEB_METHODOLOGIES_FULL
    for name in web_docs:
        _copy_doc(
            PAYLOAD_DIR / name,
            CORE_DIR,
            "04_web_methodologies",
            "tier1",
            f"Web exploitation methodology for {Path(name).stem}",
            manifest,
            seen,
            dry_run,
        )

    if profile == "hot":
        middleware = MIDDLEWARE_CORE
        apache = APACHE_CORE
    else:
        middleware = sorted(
            p.name
            for p in VULHUB_DIR.glob("*.md")
            if not p.name.startswith("base__")
        )
        apache = APACHE_CORE

    for name in middleware:
        _copy_doc(
            VULHUB_DIR / name,
            CORE_DIR,
            "01_middleware_and_cve",
            "tier2" if name in MIDDLEWARE_CORE else "tier3",
            f"Vulnerability reproduction and exploit chain for {Path(name).stem}",
            manifest,
            seen,
            dry_run,
        )

    for subdir, name in apache:
        _copy_doc(
            CLEAN_DIR / subdir / name,
            CORE_DIR,
            "01_middleware_and_cve" if subdir.startswith("03_") else "03_network_services",
            "tier2",
            f"Apache/DNS service or exploit guide for {Path(name).stem}",
            manifest,
            seen,
            dry_run,
        )

    _write_manifest(CORE_DIR / "manifest.json", manifest, dry_run)
    return manifest


def build_lookup(dry_run: bool) -> List[Dict[str, Any]]:
    _reset_dir(LOOKUP_DIR, dry_run)
    manifest: List[Dict[str, Any]] = []
    seen: Set[Path] = set()

    for src in sorted(CREDS_DIR.glob("*.md")):
        _copy_doc(
            src,
            LOOKUP_DIR,
            "creds",
            "lookup",
            f"Default credential list for {src.stem}",
            manifest,
            seen,
            dry_run,
            {"priority": "lookup"},
        )

    for stem in GTFOBINS_CORE:
        src = GTFOBINS_DIR / f"{stem}.md"
        _copy_doc(
            src,
            LOOKUP_DIR,
            "gtfobins",
            "lookup",
            f"GTFOBins command snippets for {stem}",
            manifest,
            seen,
            dry_run,
            {"priority": "core" if stem in GTFOBINS_PRIORITY else "extended"},
        )

    if not dry_run:
        (LOOKUP_DIR / "README.md").write_text(LOOKUP_README, encoding="utf-8")
    _write_manifest(LOOKUP_DIR / "manifest.json", manifest, dry_run)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the curated PenAgent knowledge core and lookup tables.")
    parser.add_argument(
        "--profile",
        choices=("hot", "full"),
        default="hot",
        help="hot = Tier 1 + representative CVE docs (default); full = all non-stub vulhub docs.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the plan without writing or deleting anything.")
    parser.add_argument("--skip-lookup", action="store_true", help="Do not rebuild data/knowledge_lookup.")
    args = parser.parse_args()

    print(f"Project root : {PROJECT_ROOT}")
    print(f"Profile      : {args.profile}")
    print(f"Dry run      : {args.dry_run}")
    print()

    core_manifest = build_core(args.profile, args.dry_run)
    _summary(f"KNOWLEDGE CORE ({args.profile})", core_manifest)

    if not args.skip_lookup:
        lookup_manifest = build_lookup(args.dry_run)
        _summary("KNOWLEDGE LOOKUP (not indexed by LightRAG)", lookup_manifest)

    if not args.dry_run:
        print()
        print(f"Core  : {CORE_DIR}")
        print(f"Lookup: {LOOKUP_DIR}")
        print("Next  : python scripts/build_knowledge_graph.py --core")


if __name__ == "__main__":
    main()
