import os
import json

rancher_secret = os.environ.get("RANCHER_ACCESS_SECRET_VALUE")

if rancher_secret:
    try:
        parsed = json.loads(rancher_secret)
        print("🔐 Rancher Secret:")
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print("⚠️ Secret is not valid JSON:")
        print(rancher_secret)
else:
    print("❌ RANCHER_ACCESS_SECRET_VALUE is not set.")