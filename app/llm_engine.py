import requests

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "qwen2.5:3b"


def generate_response(command: str, cwd: str) -> str:
    """
    Used by router for honeypot command simulation.
    """
    prompt = f"""You are a Linux terminal.
Current directory: {cwd}
User command: {command}
Provide realistic terminal output only.
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        if response.status_code != 200:
            return "command not found"

        data = response.json()
        return data.get("response", "").strip()

    except Exception:
        return "command not found"


def generate_analysis(prompt: str) -> str:
    """
    Used by threat_summary.py
    """
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        if response.status_code != 200:
            return ""

        data = response.json()
        return data.get("response", "").strip()

    except Exception:
        return ""