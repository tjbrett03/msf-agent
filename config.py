import os

# Target scope. Every network-touching tool validates against this list.
AUTHORIZED_SCOPE = [
    "192.168.56.101",  # Metasploitable 2 (VirtualBox host-only)
]

# Ollama
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

# Metasploit RPC
MSF_HOST = os.getenv("MSF_HOST", "127.0.0.1")
MSF_PORT = int(os.getenv("MSF_PORT", "55553"))
MSF_USER = os.getenv("MSF_USER", "msf")
MSF_PASS = os.getenv("MSF_PASS", "msf")
MSF_SSL  = os.getenv("MSF_SSL", "true").lower() == "true"

# SQLite
DB_PATH = os.path.expanduser(os.getenv("DB_PATH", "~/msf-agent/db/agent.db"))

# NVD API (optional -- raises rate limit from 5 to 50 req/30s)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Agentic loop hard limits
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "50"))
MAX_DURATION   = int(os.getenv("MAX_DURATION", "3600"))  # seconds
