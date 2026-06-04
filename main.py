import sys
import json

import config
import orchestrator


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target:
        print(f"Usage: python main.py <target-ip>")
        print(f"Authorized scope: {config.AUTHORIZED_SCOPE}")
        sys.exit(1)

    if target not in config.AUTHORIZED_SCOPE:
        print(f"Error: {target} is not in authorized scope {config.AUTHORIZED_SCOPE}")
        sys.exit(1)

    print(f"Starting engagement against {target}")
    result = orchestrator.run(target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
