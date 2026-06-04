"""
Quick end-to-end smoke test against the real Ollama model.
No live target required. Sets tight iteration/time limits so it
finishes fast. Prints every tool call and result to stdout.
"""
import json
import os
import sys
import tempfile

_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DB_PATH"] = _tmp.name
os.environ["MAX_ITERATIONS"] = "10"
os.environ["MAX_DURATION"] = "120"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
import orchestrator

target = config.AUTHORIZED_SCOPE[0]
print(f"Target: {target}")
print(f"Model:  {config.OLLAMA_MODEL}")
print(f"Limits: {config.MAX_ITERATIONS} iterations / {config.MAX_DURATION}s")
print("-" * 60)

result = orchestrator.run(target)

print("-" * 60)
print("FINAL RESULT:")
print(json.dumps(result, indent=2))
