import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag.lightrag_service import PenAgentLightRAG
from utils.log_common import build_logger

logger = build_logger()

CLEAN_DIR = Path(r"C:\Users\Favor\Desktop\PenAgent\data\knowledge_clean")
CORE_DIR = Path(r"C:\Users\Favor\Desktop\PenAgent\data\knowledge_core")
RECORD_FILE = Path(r"C:\Users\Favor\Desktop\PenAgent\data\lightrag_store\indexed_files.json")

CATEGORIES = {
    "vulhub": CLEAN_DIR / "03_vulhub_exploit_chains",
    "hacktricks": CLEAN_DIR / "01_hacktricks_attack_chains",
    "gtfobins": CLEAN_DIR / "02_gtfobins_privesc",
    "creds": CLEAN_DIR / "06_middleware_default_creds",
    "payloads": CLEAN_DIR / "05_payload_methodologies",
    "nuclei": CLEAN_DIR / "04_cve_threat_catalog",
}


def load_indexed_records() -> set:
    if RECORD_FILE.exists():
        try:
            return set(json.loads(RECORD_FILE.read_text(encoding="utf-8")))
        except Exception:
            return set()
    return set()


def save_indexed_records(records: set):
    RECORD_FILE.parent.mkdir(parents=True, exist_ok=True)
    RECORD_FILE.write_text(json.dumps(list(records), indent=2), encoding="utf-8")


async def index_files(files: List[Path], batch_size: int = 5):
    rag_service = PenAgentLightRAG.get_instance()
    indexed_set = load_indexed_records()

    to_process = [f for f in files if str(f) not in indexed_set]
    total = len(to_process)
    logger.info(f"Total files to index: {total} (Already indexed: {len(indexed_set)})")

    if total == 0:
        logger.success("All target documents are already indexed!")
        return

    processed = 0
    for i in range(0, total, batch_size):
        batch = to_process[i : i + batch_size]
        for f in batch:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                if len(content.strip()) < 50:
                    continue
                # Add source tag for LightRAG
                doc_text = f"Source Document: {f.name}\n\n{content}"
                await rag_service.ainsert(doc_text)
                indexed_set.add(str(f))
                processed += 1
                logger.info(f"[{processed}/{total}] Indexed: {f.name}")
            except Exception as e:
                logger.error(f"Failed to index {f.name}: {e}")

        save_indexed_records(indexed_set)

    logger.success(f"Batch indexing finished! Total newly processed: {processed} files.")


def main():
    parser = argparse.ArgumentParser(description="Build/Update PenAgent LightRAG Knowledge Graph")
    parser.add_argument("--core", action="store_true", help="Index the hot core from data/knowledge_core (default)")
    parser.add_argument("--tier1", action="store_true", help="Legacy broad Tier 1 (Vulhub, HackTricks, GTFOBins, Creds)")
    parser.add_argument("--category", choices=list(CATEGORIES.keys()), help="Index a specific category")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of documents to index")
    parser.add_argument("--all", action="store_true", help="Index all cleaned documents")

    args = parser.parse_args()

    target_files: List[Path] = []

    if args.core or (not args.tier1 and not args.category and not args.all):
        # Default to the curated hot core (Tier 1 + representative CVE docs).
        if CORE_DIR.exists():
            target_files = sorted(list(CORE_DIR.glob("**/*.md")))
    elif args.category:
        cat_dir = CATEGORIES[args.category]
        if cat_dir.exists():
            target_files.extend(list(cat_dir.glob("*.md")))
    elif args.tier1:
        # Legacy broad selection, including lookup material.
        for cat in ["vulhub", "hacktricks", "gtfobins", "creds"]:
            cat_dir = CATEGORIES[cat]
            if cat_dir.exists():
                target_files.extend(list(cat_dir.glob("*.md")))
    elif args.all:
        for cat_dir in CATEGORIES.values():
            if cat_dir.exists():
                target_files.extend(list(cat_dir.glob("*.md")))

    if args.limit:
        target_files = target_files[: args.limit]

    logger.info(f"Collected {len(target_files)} candidate documents for indexing.")
    asyncio.run(index_files(target_files))


if __name__ == "__main__":
    main()
