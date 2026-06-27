import os
import requests
from dotenv import load_dotenv

load_dotenv()


def get_github_config():
    return {
        "repo": os.getenv("GITHUB_REPO", ""),
        "token": os.getenv("GITHUB_TOKEN", ""),
        "groq_key": os.getenv("GROQ_API_KEY", ""),
    }


def get_latest_workflow_runs(repo: str, token: str = "", limit: int = 5):
    url = f"https://api.github.com/repos/{repo}/actions/runs?per_page={limit}"

    headers = {"Accept": "application/vnd.github+json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.get(url, headers=headers, timeout=20)

    if response.status_code != 200:
        return {
            "error": True,
            "message": f"GitHub API error: {response.status_code} - {response.text}",
        }

    return {
        "error": False,
        "runs": response.json().get("workflow_runs", []),
    }