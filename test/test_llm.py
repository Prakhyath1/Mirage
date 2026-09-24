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