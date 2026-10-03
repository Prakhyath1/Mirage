"""Live Ollama smoke script (prototype v1) — not part of the offline suite.

Run manually against a running Ollama:  python test/test_llm.py
The main guard keeps ``unittest discover`` from firing the network call at
import time.
"""


def main() -> None:
    import requests

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "phi3:mini",
            "prompt": """
You are Ubuntu 22.04 bash.
Only output raw terminal output.
No explanation.
No commentary.

$ uname -a
""",
            "stream": False,
            "options": {
                "temperature": 0.2
            }
        }
    )

    print(response.json()["response"])


if __name__ == "__main__":
    main()