# Suspicious URLs and endpoints

# Hardcoded S3 endpoint with potential access key
S3_BUCKET = "https://my-bucket.s3.amazonaws.com/path/to/file/AKIAIOSFODNN7EXAMPLE"

# Hardcoded API endpoint
API_ENDPOINT = "https://api.example.com/v1/users"

# Direct IP address URL
INTERNAL_API = "http://192.168.1.100:8080/api"

# Pastebin URL (potential leaked content)
LEAKED_CONFIG = "https://pastebin.com/abc123def"

# Local development endpoint (might indicate dev config)
LOCALHOST = "http://localhost:3000"

# Insecure FTP URL
FTP_URL = "ftp://files.example.com/documents"

# HTTP (not HTTPS) for AWS
INSECURE_AWS = "http://my-bucket.s3.amazonaws.com"

# Tor hidden service
ONION_SITE = "http://example.onion/private"

# Suspicious domain
TEST_DOMAIN = "http:// suspicious.bit"

# Safe - using environment variable
SAFE_URL = os.getenv("API_BASE_URL", "https://api.example.com")
