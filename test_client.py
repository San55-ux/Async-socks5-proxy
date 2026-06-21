# test_client.py
"""
Raw socket-based test client for SOCKS5 Proxy Server.
Verifies handshakes, authentication, and HTTP request routing without any external dependencies.
"""

import socket
import struct
import sys
import argparse

# Protocol codes matching RFC 1928 / RFC 1929
VER_5 = 5
METHOD_NO_AUTH = 0x00
METHOD_USER_PASS = 0x02
CMD_CONNECT = 0x01
ATYP_DOMAIN = 0x03
REP_SUCCESS = 0x00


def run_socks5_client(proxy_host, proxy_port, dest_host, dest_port, username=None, password=None):
    print(f"[*] Connecting to SOCKS5 Proxy at {proxy_host}:{proxy_port}...")
    
    # 1. Establish TCP socket connection to SOCKS5 proxy
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((proxy_host, proxy_port))
    except Exception as e:
        print(f"[!] Failed to connect to SOCKS5 Proxy: {e}")
        return False

    try:
        # 2. Greeting & Auth negotiation
        # Support user/pass method if credentials are provided, otherwise support No Auth
        methods = [METHOD_NO_AUTH]
        if username and password:
            methods.append(METHOD_USER_PASS)
            
        print(f"[*] Sending greeting. Offerd auth methods: {methods}")
        # Packet format: VER, NMETHODS, METHODS...
        greeting = struct.pack(f"!BB{len(methods)}B", VER_5, len(methods), *methods)
        sock.sendall(greeting)

        # Read server reply
        reply = sock.recv(2)
        if len(reply) < 2:
            print("[!] Server disconnected during greeting.")
            return False
            
        ver, selected_method = struct.unpack("!BB", reply)
        print(f"[+] Proxy server selected Auth Method: {selected_method}")
        
        if ver != VER_5:
            print(f"[!] Server returned invalid version: {ver}")
            return False

        # 3. Handle subnegotiation if Username/Password Auth is selected
        if selected_method == METHOD_USER_PASS:
            if not username or not password:
                print("[!] Server requested username/pass authentication, but none provided.")
                return False
                
            print(f"[*] Authenticating with user: '{username}'")
            # Subnegotiation format: SUB_VER (1), ULEN (1), UNAME (var), PLEN (1), PASSWD (var)
            u_bytes = username.encode("utf-8")
            p_bytes = password.encode("utf-8")
            auth_header = struct.pack("!BB", 1, len(u_bytes))
            auth_packet = auth_header + u_bytes + struct.pack("!B", len(p_bytes)) + p_bytes
            
            sock.sendall(auth_packet)
            
            # Read auth reply
            auth_reply = sock.recv(2)
            if len(auth_reply) < 2:
                print("[!] Server disconnected during authentication.")
                return False
            sub_ver, auth_status = struct.unpack("!BB", auth_reply)
            
            if auth_status != 0x00:
                print(f"[!] Authentication failed with status code: {auth_status}")
                return False
            print("[+] Authentication Succeeded.")

        elif selected_method == 0xFF:
            print("[!] Proxy server rejected all authentication methods.")
            return False

        # 4. Send Connect request to target host
        print(f"[*] Requesting connection to destination target {dest_host}:{dest_port}...")
        # Request format: VER (1), CMD (1), RSV (1), ATYP (1), DST.ADDR (var), DST.PORT (2)
        dest_bytes = dest_host.encode("utf-8")
        req_header = struct.pack("!BBBB", VER_5, CMD_CONNECT, 0x00, ATYP_DOMAIN)
        req_addr = struct.pack("!B", len(dest_bytes)) + dest_bytes
        req_port = struct.pack("!H", dest_port)
        
        sock.sendall(req_header + req_addr + req_port)

        # Read connection reply
        resp_header = sock.recv(4)
        if len(resp_header) < 4:
            print("[!] Server disconnected during request response.")
            return False
            
        ver, rep, rsv, atyp = struct.unpack("!BBBB", resp_header)
        
        # Read the rest of bound IP/port to clean stream buffer
        if atyp == 1:    # IPv4
            sock.recv(4 + 2)
        elif atyp == 3:  # Domain Name
            len_byte = sock.recv(1)
            sock.recv(len_byte[0] + 2)
        elif atyp == 4:  # IPv6
            sock.recv(16 + 2)

        if rep != REP_SUCCESS:
            print(f"[!] Proxy failed to connect to destination. Status reply code: {rep}")
            return False
            
        print(f"[+] Tunnel successfully established to {dest_host}:{dest_port}!")

        # 5. Send actual HTTP request over the tunnel
        print("[*] Sending HTTP GET request...")
        http_request = (
            f"GET /ip HTTP/1.1\r\n"
            f"Host: {dest_host}\r\n"
            f"User-Agent: SOCKS5TestClient/1.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(http_request.encode("utf-8"))

        # Read target server response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        print("\n--- TARGET SERVER RESPONSE ---")
        print(response.decode("utf-8", errors="replace"))
        print("------------------------------\n")
        return True

    finally:
        sock.close()
        print("[*] Socket connection closed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test client for SOCKS5 proxy server.")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="SOCKS5 Proxy IP (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=1080, help="SOCKS5 Proxy Port (default: 1080)")
    parser.add_argument("--dest-host", default="httpbin.org", help="Target host (default: httpbin.org)")
    parser.add_argument("--dest-port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--username", help="Auth Username")
    parser.add_argument("--password", help="Auth Password")
    
    args = parser.parse_args()
    
    success = run_socks5_client(
        args.proxy_host,
        args.proxy_port,
        args.dest_host,
        args.dest_port,
        args.username,
        args.password
    )
    sys.exit(0 if success else 1)
