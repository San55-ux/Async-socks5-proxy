# server.py
"""
Asynchronous SOCKS5 Proxy Server with Real-time Dashboard HTTP Engine.
Uses asyncio streams to handle concurrent SOCKS5 connections and serve SSE updates.
"""

import asyncio
import logging
import socket
import sys
import time
import json
import os

import config
from protocol import (
    negotiate_auth_method,
    authenticate_user,
    parse_request,
    build_reply,
    SOCKSProtocolError,
    CMD_CONNECT,
    ATYP_IPV4,
    ATYP_IPV6,
    REP_SUCCESS,
    REP_GEN_FAILURE,
    REP_CONN_REFUSED,
    REP_HOST_UNREACHABLE,
    REP_CMD_NOT_SUPPORTED
)

# Setup logging
logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)
logger = logging.getLogger("socks5.server")

# --- Dashboard Real-Time Metrics & State ---
STATS = {
    "active_connections": 0,
    "total_connections": 0,
    "bytes_sent": 0,       # Downstream (Remote -> Proxy -> Client)
    "bytes_received": 0,   # Upstream (Client -> Proxy -> Remote)
    "failed_logins": 0,
    "uptime_start": time.time()
}

# Active HTTP Server-Sent Event (SSE) client queues
SSE_CLIENTS = set()


def broadcast_event(event_type, **kwargs):
    """Broadcasts a SOCKS event to all connected dashboard browsers."""
    if not SSE_CLIENTS:
        return
    payload = {
        "event": event_type,
        "stats": STATS,
        **kwargs
    }
    msg = json.dumps(payload)
    for client_queue in list(SSE_CLIENTS):
        try:
            client_queue.put_nowait(msg)
        except Exception:
            pass


async def pipe(reader, writer, is_upstream=True):
    """
    Pipes data from reader to writer asynchronously.
    Increments metrics and sends bandwidth notifications to the dashboard.
    """
    try:
        while True:
            data = await reader.read(config.BUFFER_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()

            # Record stats
            length = len(data)
            if is_upstream:
                STATS["bytes_received"] += length
            else:
                STATS["bytes_sent"] += length

            broadcast_event("traffic")
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as e:
        logger.debug(f"Piping error: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(reader, writer):
    """
    Handles a single SOCKS5 client connection.
    Hooks into stats tracking to report activity to the dashboard stream.
    """
    client_address = writer.get_extra_info("peername")
    client_ip_port = f"{client_address[0]}:{client_address[1]}"
    logger.info(f"Incoming SOCKS5 connection from {client_address}")

    # Track metrics
    STATS["total_connections"] += 1
    STATS["active_connections"] += 1
    
    remote_writer = None
    dst_addr_port = "Unknown"
    
    try:
        # Phase 1: Greeting & Negotiation
        selected_method = await negotiate_auth_method(reader, writer, config.REQUIRE_AUTH)
        
        # Phase 2: Authentication
        if selected_method == 0x02:
            try:
                await authenticate_user(reader, writer, config.USERS)
            except SOCKSProtocolError as ae:
                STATS["failed_logins"] += 1
                broadcast_event("auth_fail", client=client_ip_port, user="nokia")
                raise ae

        # Phase 3: Request Parsing
        cmd, atyp, dst_addr, dst_port = await parse_request(reader)
        dst_addr_port = f"{dst_addr}:{dst_port}"
        logger.info(f"Client {client_address} requests command={cmd} destination={dst_addr_port}")

        if cmd != CMD_CONNECT:
            reply = build_reply(REP_CMD_NOT_SUPPORTED)
            writer.write(reply)
            await writer.drain()
            raise SOCKSProtocolError(f"Unsupported SOCKS command code: {cmd}", REP_CMD_NOT_SUPPORTED)

        # Notify dashboard of connection start
        broadcast_event("connect_start", client=client_ip_port, dest=dst_addr_port)

        # Phase 4: Remote Connect
        logger.info(f"Connecting client {client_address} to target {dst_addr_port}...")
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(dst_addr, dst_port),
                timeout=10.0
            )
        except Exception as e:
            logger.error(f"Failed to connect to target {dst_addr_port}: {e}")
            reply = build_reply(REP_GEN_FAILURE)
            writer.write(reply)
            await writer.drain()
            return

        local_sock = remote_writer.get_extra_info("sockname")
        bind_ip, bind_port = local_sock[0], local_sock[1]
        reply_atyp = ATYP_IPV6 if ":" in bind_ip else ATYP_IPV4

        reply = build_reply(REP_SUCCESS, atyp=reply_atyp, bind_addr=bind_ip, bind_port=bind_port)
        writer.write(reply)
        await writer.drain()

        # Phase 5: Bidirectional Piping
        logger.info(f"Tunnel established: {client_address} <--> {dst_addr_port}")
        
        pipe_client_to_remote = asyncio.create_task(pipe(reader, remote_writer, is_upstream=True))
        pipe_remote_to_client = asyncio.create_task(pipe(remote_reader, writer, is_upstream=False))

        done, pending = await asyncio.wait(
            [pipe_client_to_remote, pipe_remote_to_client],
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()
            
        await asyncio.gather(*pending, return_exceptions=True)
        logger.info(f"Tunnel closed between {client_address} and {dst_addr_port}")

    except SOCKSProtocolError as e:
        logger.warning(f"Protocol error with client {client_address}: {e}")
    except asyncio.IncompleteReadError:
        logger.debug(f"Client {client_address} disconnected during handshake")
    except Exception as e:
        logger.exception(f"Unhandled error with client {client_address}: {e}")
    finally:
        STATS["active_connections"] = max(0, STATS["active_connections"] - 1)
        broadcast_event("connect_end", client=client_ip_port, dest=dst_addr_port)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        if remote_writer:
            try:
                remote_writer.close()
                await remote_writer.wait_closed()
            except Exception:
                pass


# --- Async HTTP Dashboard Server ---
async def handle_http_client(reader, writer):
    """Serves the static dashboard HTML page and streams real-time logs via SSE."""
    try:
        request_line = await reader.readline()
        if not request_line:
            return
        parts = request_line.decode('utf-8', errors='ignore').split()
        if len(parts) < 2:
            return
        method, path = parts[0], parts[1]

        # Flush request headers
        while True:
            line = await reader.readline()
            if not line or line == b'\r\n':
                break

        if method == "GET":
            if path == "/":
                # Serve dashboard.html
                try:
                    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
                    with open(dashboard_path, "r", encoding="utf-8") as f:
                        html = f.read()
                    
                    content = html.encode('utf-8')
                    headers = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(content)}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode('utf-8')
                    writer.write(headers + content)
                    await writer.drain()
                except Exception as e:
                    logger.error(f"Error serving dashboard.html: {e}")
                    writer.write(b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n")
                    await writer.drain()

            elif path == "/events":
                # Stream real-time logs via SSE (Server-Sent Events)
                headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: keep-alive\r\n"
                    "Access-Control-Allow-Origin: *\r\n\r\n"
                ).encode('utf-8')
                writer.write(headers)
                await writer.drain()

                # Add a queue for this connection to receive live broadcasts
                client_queue = asyncio.Queue()
                SSE_CLIENTS.add(client_queue)

                # Push initial snapshot
                initial_msg = json.dumps({"event": "initial", "stats": STATS})
                writer.write(f"data: {initial_msg}\n\n".encode('utf-8'))
                await writer.drain()

                try:
                    while True:
                        msg = await client_queue.get()
                        writer.write(f"data: {msg}\n\n".encode('utf-8'))
                        await writer.drain()
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                    pass
                finally:
                    SSE_CLIENTS.discard(client_queue)
            else:
                writer.write(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
                await writer.drain()
    except Exception as e:
        logger.debug(f"HTTP server error: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    """Starts the asyncio SOCKS5 server and HTTP Dashboard Server concurrently."""
    socks_server = await asyncio.start_server(
        handle_client,
        config.HOST,
        config.PORT,
        reuse_address=True
    )
    
    http_server = await asyncio.start_server(
        handle_http_client,
        config.HTTP_HOST,
        config.HTTP_PORT,
        reuse_address=True
    )

    socks_addr = socks_server.sockets[0].getsockname()
    http_addr = http_server.sockets[0].getsockname()
    logger.info(f"SOCKS5 Proxy Server listening on {socks_addr}")
    logger.info(f"HTTP Dashboard Server listening on http://{http_addr[0]}:{http_addr[1]}")

    async with socks_server, http_server:
        await asyncio.gather(
            socks_server.serve_forever(),
            http_server.serve_forever()
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Proxy server shut down by user.")
    except Exception as e:
        logger.critical(f"Server crashed: {e}")
        sys.exit(1)
