# Configuration file with hardcoded secrets
import os

# AWS Credentials (should be detected)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub token (should be detected)
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# Database connection (should be detected)
DATABASE_URL = "postgres://user:password123@localhost:5432/mydb"

# Stripe API key (should be detected) - TEST DATA, NOT A REAL KEY
STRIPE_API_KEY = "sk_test_fake1234567890abcdefghijklmnopqrstuv"

# JWT token (should be detected)
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Slack token (should be detected)
SLACK_TOKEN = "xoxb-1234567890-1234567890123-456789012345"

# Password (should be detected)
PASSWORD = "MySuperSecretPassword123!"

# Environment variables (safe)
API_ENDPOINT = os.getenv("API_ENDPOINT", "https://api.example.com")
