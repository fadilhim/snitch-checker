# Safe configuration file using environment variables
import os
from typing import Optional

class Config:
    # Using environment variables (safe)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///local.db")
    API_KEY: str = os.getenv("API_KEY", "")
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")

    # Safe base URL
    API_BASE_URL: str = os.getenv("API_BASE_URL", "https://api.example.com")

    # Safe file operations
    def get_config_path(self) -> str:
        """Get config path safely"""
        return os.path.join(os.path.expanduser("~"), ".config", "app")

    # Safe subprocess usage
    def run_command(self, args: list[str]) -> int:
        """Run command safely without shell"""
        import subprocess
        return subprocess.run(args, check=False).returncode

# Safe JSON loading
import json

def load_config(path: str) -> dict:
    """Load config safely"""
    with open(path, "r") as f:
        return json.load(f)

# Safe constants
DATABASE_PORT = 5432
TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
