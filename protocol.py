# protocol.py
"""
SOCKS5 Protocol Parser (RFC 1928 & RFC 1929).
Handles packet decoding, validation, and encoding of server responses.
"""

import struct
import socket
import logging

logger = logging.getLogger("socks5.protocol")

# SOCKS Constants
SOCKS_VERSION = 0x05
SUBNEGOTIATION_VERSION = 0x01

# Command Types
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address Types (ATYP)
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Authentication Methods
METHOD_NO_AUTH = 0x00
METHOD_USER_PASS = 0x02
METHOD_NO_ACCEPTABLE = 0xFF

# Reply Status Codes
REP_SUCCESS = 0x00
REP_GEN_FAILURE = 0x01
REP_CONN_NOT_ALLOWED = 0x02
REP_NET_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONN_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ADDR_TYPE_NOT_SUPPORTED = 0x08


class SOCKSProtocolError(Exception):
    """Custom exception representing SOCKS5 protocol violations."""
    def __init__(self, message, reply_code=REP_GEN_FAILURE):
        super().__init__(message)
        self.reply_code = reply_code


async def negotiate_auth_method(reader, writer, require_auth=False):
    """
    Handles the SOCKS5 greeting/negotiation phase.
    
    RFC 1928 greeting format:
    +----+----------+----------+
    |VER | NMETHODS | METHODS  |
    +----+----------+----------+
    | 1  |    1     | 1 to 255 |
    +----+----------+----------+
    """
    header = await reader.readexactly(2)
    ver, nmethods = struct.unpack("!BB", header)

    if ver != SOCKS_VERSION:
        raise SOCKSProtocolError(f"Unsupported SOCKS version: {ver}")

    methods = await reader.readexactly(nmethods)
    logger.debug(f"Client offered auth methods: {list(methods)}")

    # Select method
    if require_auth:
        if METHOD_USER_PASS in methods:
            selected_method = METHOD_USER_PASS
        else:
            selected_method = METHOD_NO_ACCEPTABLE
    else:
        if METHOD_NO_AUTH in methods:
            selected_method = METHOD_NO_AUTH
        else:
            selected_method = METHOD_NO_ACCEPTABLE

    # Send selection response
    writer.write(struct.pack("!BB", SOCKS_VERSION, selected_method))
    await writer.drain()

    if selected_method == METHOD_NO_ACCEPTABLE:
        raise SOCKSProtocolError("No acceptable authentication methods offered by client")

    return selected_method


async def authenticate_user(reader, writer, users_db):
    """
    Handles Username/Password subnegotiation (RFC 1929).
    
    RFC 1929 format:
    +----+------+----------+------+----------+
    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    +----+------+----------+------+----------+
    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    +----+------+----------+------+----------+
    """
    header = await reader.readexactly(2)
    ver, ulen = struct.unpack("!BB", header)

    if ver != SUBNEGOTIATION_VERSION:
        raise SOCKSProtocolError(f"Unsupported auth subnegotiation version: {ver}")

    username_bytes = await reader.readexactly(ulen)
    username = username_bytes.decode("utf-8", errors="replace")

    plen_byte = await reader.readexactly(1)
    plen = plen_byte[0]

    password_bytes = await reader.readexactly(plen)
    password = password_bytes.decode("utf-8", errors="replace")

    # Validate credentials
    authenticated = users_db.get(username) == password
    status = 0x00 if authenticated else 0x01

    # Send auth response
    writer.write(struct.pack("!BB", SUBNEGOTIATION_VERSION, status))
    await writer.drain()

    if not authenticated:
        raise SOCKSProtocolError(f"Authentication failed for user: '{username}'")

    logger.info(f"User '{username}' authenticated successfully")
    return username


async def parse_request(reader):
    """
    Parses the client's connection request details.
    
    RFC 1928 Request format:
    +----+-----+-------+------+----------+----------+
    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    """
    header = await reader.readexactly(4)
    ver, cmd, rsv, atyp = struct.unpack("!BBBB", header)

    if ver != SOCKS_VERSION:
        raise SOCKSProtocolError(f"Invalid request version: {ver}")
    if cmd not in (CMD_CONNECT, CMD_BIND, CMD_UDP_ASSOCIATE):
        raise SOCKSProtocolError(f"Unsupported command code: {cmd}", REP_CMD_NOT_SUPPORTED)

    # Parse address based on Address Type (ATYP)
    if atyp == ATYP_IPV4:
        addr_bytes = await reader.readexactly(4)
        dst_addr = socket.inet_ntoa(addr_bytes)
    elif atyp == ATYP_DOMAIN:
        len_byte = await reader.readexactly(1)
        domain_len = len_byte[0]
        domain_bytes = await reader.readexactly(domain_len)
        dst_addr = domain_bytes.decode("utf-8", errors="replace")
    elif atyp == ATYP_IPV6:
        addr_bytes = await reader.readexactly(16)
        dst_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        raise SOCKSProtocolError(f"Address type not supported: {atyp}", REP_ADDR_TYPE_NOT_SUPPORTED)

    # Read port (2 bytes, Big-Endian)
    port_bytes = await reader.readexactly(2)
    dst_port = struct.unpack("!H", port_bytes)[0]

    return cmd, atyp, dst_addr, dst_port


def build_reply(rep_code, atyp=ATYP_IPV4, bind_addr="0.0.0.0", bind_port=0):
    """
    Builds the SOCKS5 server reply packet.
    
    RFC 1928 Reply format:
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    """
    ver = SOCKS_VERSION
    rsv = 0x00

    # Pack bind address bytes
    if atyp == ATYP_IPV4:
        addr_bytes = socket.inet_aton(bind_addr)
    elif atyp == ATYP_DOMAIN:
        domain_bytes = bind_addr.encode("utf-8")
        addr_bytes = bytes([len(domain_bytes)]) + domain_bytes
    elif atyp == ATYP_IPV6:
        addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr)
    else:
        addr_bytes = b"\x00\x00\x00\x00"

    reply_header = struct.pack("!BBBB", ver, rep_code, rsv, atyp)
    port_bytes = struct.pack("!H", bind_port)

    return reply_header + addr_bytes + port_bytes
