# config.py
"""
Configuration settings for the SOCKS5 Proxy Server.
Allows users to modify host binding, port, authentication rules, and buffer sizing.
"""

# Networking Configuration
HOST = "127.0.0.1"  # Set to "0.0.0.0" to listen on all interfaces
PORT = 1080        # Standard SOCKS5 proxy port

# Performance Configuration
BUFFER_SIZE = 8192  # Size of buffer for copying data packets (in bytes)

# Authentication Configuration
REQUIRE_AUTH = False  # Set to True to enforce username/password auth (RFC 1929)
USERS = {
    "nokia": "telecom123",
    "admin": "adminpassword"
}

# Logging configuration
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# HTTP Dashboard Server Configuration
HTTP_HOST = "127.0.0.1"  # Set to "0.0.0.0" to expose dashboard on network
HTTP_PORT = 8080        # Port to access the web dashboard

