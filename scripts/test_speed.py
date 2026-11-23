import asyncio
import sys
import time
import torch
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rag.lightrag_service import PenAgentLightRAG

CLEAN_DIR = Path(r"C:\Users\Favor\Desktop\PenAgent\data\knowledge_clean")

TEST_FILES = [
    CLEAN_DIR / "03_vulhub_exploit_chains" / "redis__4-unacc.md",
    CLEAN_DIR / "03_vulhub_exploit_chains" / "spring__CVE-2022-22965.md",
    CLEAN_DIR / "02_gtfobins_privesc" / "find.md",
    CLEAN_DIR / "01_hacktricks_attack_chains" / "network-services-pentesting__pentesting-ssh.md",
]

async def run_benchmark():
    print("=" * 60)
    print("LIGHTRAG INGESTION SPEED BENCHMARK")
    print("=" * 60)

    # 1. Initialize LightRAG service
    t0 = time.perf_counter()
    rag_service = PenAgentLightRAG.get_instance()
    await rag_service.ensure_initialized()
    init_time = time.perf_counter() - t0
    print(f"Service & Model warm-up time: {init_time:.2f}s")
    print(f"GPU VRAM in use: {torch.cuda.memory_allocated() / (1024**3):.2f} GB\n")

    results = []
    total_start = time.perf_counter()

    for idx, f in enumerate(TEST_FILES, 1):
        if not f.exists():
            print(f"[-] File not found: {f}")
            continue

        content = f.read_text(encoding="utf-8", errors="replace")
        char_len = len(content)
        doc_text = f"Source Document: {f.name}\n\n{content}"

        print(f"[{idx}/{len(TEST_FILES)}] Indexing: {f.name} ({char_len} chars)...")
        t_file_start = time.perf_counter()
        
        try:
            await rag_service.ainsert(doc_text)
            elapsed = time.perf_counter() - t_file_start
            print(f"    -> Done in {elapsed:.2f}s")
            results.append({
                "file": f.name,
                "chars": char_len,
                "time_sec": elapsed,
                "success": True
            })
        except Exception as e:
            elapsed = time.perf_counter() - t_file_start
            print(f"    -> Failed in {elapsed:.2f}s: {e}")
            results.append({
                "file": f.name,
                "chars": char_len,
                "time_sec": elapsed,
                "success": False,
                "error": str(e)
            })

    total_time = time.perf_counter() - total_start
    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"Total documents tested: {len(results)}")
    print(f"Total elapsed time: {total_time:.2f}s")
    avg_time = sum(r["time_sec"] for r in results) / len(results) if results else 0
    print(f"Average time per document: {avg_time:.2f}s")
    print(f"Peak VRAM allocated: {torch.cuda.max_memory_allocated() / (1024**3):.2f} GB")
    print("-" * 60)
    for r in results:
        status = "OK" if r["success"] else "ERR"
        print(f"[{status}] {r['file'][:45]:<45} | {r['chars']:>5} chars | {r['time_sec']:>5.2f}s")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_benchmark())
