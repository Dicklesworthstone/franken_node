import glob
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

logger = configure_test_logging("run_all_checks")
logger.info("starting run_all_checks", extra={"argv": sys.argv[1:]})

failed = []
for script in sorted(glob.glob("scripts/*.py")):
    if script in ["scripts/e2e_test_server.py", "scripts/program_e2e_orchestrator.py"]:
        continue
    try:
        with open(script, "r", encoding="utf-8") as f:
            content = f.read()
        args = ["python3", script]
        if "--self-test" in content:
            args.append("--self-test")
        print(f"Running: {script} ...", flush=True)
        res = subprocess.run(args, capture_output=True, text=True, timeout=3600)
        if res.returncode != 0:
            print(f"FAILED: {script}")
            print(res.stdout)
            print(res.stderr)
            failed.append(script)
        else:
            print(f"PASSED: {script}")
    except Exception as e:
        print(f"FAILED (Error/Timeout): {script} - {e}")
        failed.append(script)

print("\n--- Summary ---")
print(f"Failed scripts: {len(failed)}")
for f in failed:
    print(f)
