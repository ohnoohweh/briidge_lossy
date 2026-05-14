"""ObstacleBridge iOS companion app prototype package."""
 
import os
import time
import json

ROOT = os.environ.get("OBSTACLEBRIDGE_IOS_DOCUMENTS_ROOT", "")
LOG = os.path.join(ROOT, "logs", "ipserver-python-package-init.jsonl")

def log(event, **fields):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        payload = {
            "event": event,
            "pid": os.getpid(),
            "time": time.time(),
            **fields,
        }
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, sort_keys=True) + "\n")
            f.flush()
    except BaseException:
        pass

log("package_init_entered")

__all__ = []

log("package_init_finished")
