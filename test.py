"""Small API-key smoke test. Set GUARDX_API_KEY in the environment first."""

import os

from sdk import GuardX


def main() -> None:
    api_key = os.environ.get("GUARDX_API_KEY")
    if not api_key:
        raise SystemExit("Set GUARDX_API_KEY to a newly generated GuardX key before running this smoke test.")

    client = GuardX(api_key)
    result = client.check_input("What is the capital of France?")
    print("Decision:", result.decision)
    print("Risk:", result.risk_score, result.risk_level)
    print("Request ID:", result.request_id)


if __name__ == "__main__":
    main()
