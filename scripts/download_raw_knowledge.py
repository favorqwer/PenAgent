import os
import subprocess
import sys
from pathlib import Path

PROXY = "http://127.0.0.1:7897"
BASE_DIR = Path(r"C:\Users\Favor\Desktop\PenAgent\data\knowledge_raw")

REPOS = [
    {
        "name": "GTFOBins",
        "url": "https://github.com/GTFOBins/GTFOBins.github.io.git",
        "sparse": None,
    },
    {
        "name": "PayloadsAllTheThings",
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "sparse": None,
    },
    {
        "name": "HackTricks",
        "url": "https://github.com/carlospolop/hacktricks.git",
        "sparse": None,
    },
    {
        "name": "nuclei-templates",
        "url": "https://github.com/projectdiscovery/nuclei-templates.git",
        "sparse": None,
    },
    {
        "name": "SecLists-DefaultCredentials",
        "url": "https://github.com/danielmiessler/SecLists.git",
        "sparse": "Passwords/Default-Credentials",
    },
]

def run_git(cmd, cwd=None):
    env = os.environ.copy()
    env["HTTP_PROXY"] = PROXY
    env["HTTPS_PROXY"] = PROXY
    env["http_proxy"] = PROXY
    env["https_proxy"] = PROXY
    print(f"[{cwd or '.'}] Running: {' '.join(cmd)}")
    res = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    if res.returncode != 0:
        print(f"ERROR (exit code {res.returncode}):")
        if res.stdout:
            print("STDOUT:", res.stdout)
        if res.stderr:
            print("STDERR:", res.stderr)
        return False
    else:
        if res.stdout:
            print("STDOUT:", res.stdout.strip())
        return True

def main():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Base storage directory: {BASE_DIR}")
    print(f"Using proxy: {PROXY}")

    success_list = []
    fail_list = []

    for item in REPOS:
        name = item["name"]
        url = item["url"]
        sparse = item["sparse"]
        target_dir = BASE_DIR / name

        print(f"\n{'='*60}\nCloning: {name} from {url}\n{'='*60}")

        if target_dir.exists() and any(target_dir.iterdir()):
            print(f"Target directory {target_dir} already exists and is not empty. Skipping clone.")
            success_list.append(name)
            continue

        if sparse:
            # Sparse clone
            clone_cmd = [
                "git", "-c", f"http.proxy={PROXY}",
                "clone", "--depth", "1", "--filter=blob:none", "--sparse",
                url, str(target_dir)
            ]
            if run_git(clone_cmd):
                sparse_cmd = ["git", "sparse-checkout", "set", sparse]
                if run_git(sparse_cmd, cwd=str(target_dir)):
                    print(f"Successfully cloned and sparse-checked {name}")
                    success_list.append(name)
                else:
                    fail_list.append(name)
            else:
                fail_list.append(name)
        else:
            # Normal shallow clone
            clone_cmd = [
                "git", "-c", f"http.proxy={PROXY}",
                "clone", "--depth", "1",
                url, str(target_dir)
            ]
            if run_git(clone_cmd):
                print(f"Successfully cloned {name}")
                success_list.append(name)
            else:
                fail_list.append(name)

    print("\n" + "="*60)
    print("Download Summary:")
    print(f"Success: {success_list}")
    print(f"Failed:  {fail_list}")
    print("="*60)

if __name__ == "__main__":
    main()
