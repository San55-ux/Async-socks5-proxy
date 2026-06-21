# High-Performance SOCKS5 Proxy Server with Real-Time Web Dashboard

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![RFC Compliance](https://img.shields.io/badge/RFC-1928%20%2F%201929-orange.svg)](https://datatracker.ietf.org/doc/html/rfc1928)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-Zero%20(Standard%20Library)-brightgreen.svg)](https://docs.python.org/3/library/)

A high-performance, asynchronous SOCKS5 proxy server written from scratch in Python using `asyncio` streams. The server complies with the official **RFC 1928 (SOCKS5)** and **RFC 1929 (Username/Password authentication)** specifications. 

It features a built-in, lightweight HTTP and Server-Sent Events (SSE) server that serves a glassmorphic real-time web dashboard to monitor active connections, connection logs, and network bandwidth — all with **zero external dependencies** (no `pip install` required).

---

##  Web Dashboard Preview
The project serves a modern, dark-mode analytics console at `http://127.0.0.1:8080` showing:
*   **Active Tunnels Count:** Pulse updates showing live concurrent streams.
*   **Live Traffic Speedometer:** Cumulative upstream and downstream data counts.
*   **Terminal Log Stream:** Neon scrolling CLI log showing client sources and target mappings.
*   **Server Uptime & Handshakes:** Session performance monitoring metrics.

---

##  Architecture and Connection Flow

```
[Web Browser / Client]
        │
        │ 1. Connect (SOCKS5 Handshake - Port 1080)
        ▼
[SOCKS5 Proxy Daemon]
        │
        ├─► 2. Authenticate (Optional Username/Password - RFC 1929)
        │
        ├─► 3. Establish TCP Tunnel (CONNECT command)
        │
        └─► 4. Asynchronous Bidirectional Pipe (Using asyncio.wait) ──► [Remote Server (e.g. google.com)]
        │
        ▼ 5. Event Telemetry (Broadcasting JSON via SSE on Port 8080)
[Glassmorphic HTML5 Dashboard] (Viewed in Browser)
```

---

##  Project Structure

*   `server.py`: Dual-purpose server. Hosts SOCKS5 proxy handling and the HTTP/SSE server.
*   `protocol.py`: Byte-level protocol parser for SOCKS5 handshakes, auth subnegotiation, and requests.
*   `config.py`: Configuration interface for host bindings, authentication toggle, and users.
*   `dashboard.html`: The frontend user interface styled with glassmorphism CSS and vanilla JS.
*   `test_client.py`: Raw socket client utility to run traffic diagnostics.

---

##  Quick Start Guide

### Prerequisites
*   Python 3.7 or newer.
*   No external packages needed.

### 1. Start the Server
Navigate to the project folder and run:
```bash
python server.py
```
Outputs:
```text
2026-06-20 22:45:00,123 [INFO] socks5.server: SOCKS5 Proxy Server listening on ('127.0.0.1', 1080)
2026-06-20 22:45:00,125 [INFO] socks5.server: HTTP Dashboard Server listening on http://127.0.0.1:8080
```

### 2. Open the Web Dashboard
Open your browser and navigate to:
 **[http://127.0.0.1:8080](http://127.0.0.1:8080)**

### 3. Run Traffic and Watch Live Updates
Open a separate terminal window and run:
```bash
python test_client.py
```
You will immediately see metrics on the dashboard increment and the live console append connection events.

---

##  Enabling Authentication (RFC 1929)

To secure the proxy with Username/Password authentication:
1.  Open `config.py` and modify:
    ```python
    REQUIRE_AUTH = True
    ```
2.  Restart `server.py`.
3.  Run the client passing credentials:
    ```bash
    python test_client.py --username nokia --password telecom123
    ```

---

##  Technical Highlights for Interviews

If you are presenting this project in a software/network engineering interview (e.g. at Nokia):
*   **Standards Translation:** Shows capability to translate standardized specs (IETF RFCs) into direct, byte-level packet encoders/decoders.
*   **Non-blocking Event Loops:** Shows deep familiarity with Python's asynchronous model (`asyncio`), using tasks, stream-readers, and socket descriptors to achieve concurrency.
*   **Zero-Dependency Web Engineering:** The built-in HTTP server and Server-Sent Events engine use raw socket string parsing and data queues, demonstrating how to write clean, lightweight network software for embedded devices without relying on third-party frameworks.
