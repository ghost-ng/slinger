"""
SOCKS5 Proxy Server for Slinger
Operator-side component that accepts local SOCKS5 connections and
multiplexes them through an SMB named pipe to the proxy binary on target.
"""

import queue
import socket
import struct
import threading
import time
import traceback
from slingerpkg.utils.printlib import *


# Proxy frame message types (must match socks_channel.h ProxyFrame::Type)
CONNECT_REQ = 0x2001
CONNECT_RESP = 0x2002
DATA = 0x2003
CLOSE = 0x2004
KEEPALIVE = 0x2005
SHUTDOWN = 0x2006

# Address types (SOCKS5 compatible)
ADDR_IPV4 = 0x01
ADDR_DOMAIN = 0x03
ADDR_IPV6 = 0x04

# Connect status codes
STATUS_OK = 0x00
STATUS_REFUSED = 0x01
STATUS_UNREACHABLE = 0x02
STATUS_TIMEOUT = 0x03
STATUS_DNS_FAIL = 0x04


class SocksProxyServer:
    """Local SOCKS5 server that tunnels traffic through an SMB named pipe."""

    def __init__(self, smb_conn, pipe_tid, pipe_fid, bind_host="127.0.0.1", bind_port=1080):
        self.conn = smb_conn
        self.pipe_tid = pipe_tid
        self.pipe_fid = pipe_fid
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.next_channel_id = 1
        self.channels = {}  # channel_id -> client_socket
        self.channel_lock = threading.Lock()
        self.running = False
        self.server_socket = None
        self._connect_events = {}  # channel_id -> threading.Event
        self._connect_results = {}  # channel_id -> status byte
        self._write_queue = queue.Queue()  # frames queued for writing
        self.show_tunnel_logs = True  # show tunnel logs (set False when backgrounded)

    # ── Pipe I/O ─────────────────────────────────────────────────────────

    def _send_frame(self, msg_type, channel_id, payload=b""):
        """Queue a proxy frame for writing. Actual write happens in reader thread."""
        header = struct.pack("<III", len(payload), msg_type, channel_id)
        self._write_queue.put(header + payload)
        return True

    def _read_frame(self):
        """Read one proxy frame from the SMB pipe. Blocks until data arrives."""
        try:
            # Read 12-byte header: [length:4][type:4][channel:4]
            header = self.conn.readFile(self.pipe_tid, self.pipe_fid, 0, 12)
            if not header or len(header) == 0:
                return None, None, None
            if len(header) < 12:
                print_debug(f"Partial header: {len(header)} bytes (expected 12)")
                return None, None, None

            length, msg_type, channel_id = struct.unpack("<III", header)

            if length > 65536:
                print_debug(f"Frame too large: {length}")
                return None, None, None

            payload = b""
            if length > 0:
                payload = self.conn.readFile(self.pipe_tid, self.pipe_fid, 0, length)
                if not payload or len(payload) != length:
                    print_debug(
                        f"Incomplete payload: got {len(payload) if payload else 0}, expected {length}"
                    )
                    return None, None, None

            return msg_type, channel_id, payload

        except Exception as e:
            if self.running:
                err_str = str(e)
                if "STATUS_PIPE_BROKEN" in err_str or "STATUS_PIPE_DISCONNECTED" in err_str:
                    print_debug(f"Pipe disconnected: {e}")
                else:
                    print_debug(f"Pipe read error: {e}")
            return None, None, None

    # ── SOCKS5 Negotiation ───────────────────────────────────────────────

    def _socks5_handshake(self, client_sock):
        """Perform SOCKS5 handshake. Returns (addr_type, host, port) or None."""
        try:
            # Method negotiation
            data = client_sock.recv(2)
            if len(data) < 2 or data[0] != 0x05:
                return None
            nmethods = data[1]
            methods = client_sock.recv(nmethods)

            # Accept no-auth (0x00) — it's localhost
            client_sock.sendall(b"\x05\x00")

            # Connection request
            data = client_sock.recv(4)
            if len(data) < 4 or data[0] != 0x05 or data[1] != 0x01:
                # Only CONNECT supported
                client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return None

            addr_type = data[3]
            if addr_type == ADDR_IPV4:
                addr_data = client_sock.recv(4)
                host = socket.inet_ntoa(addr_data)
                port_data = client_sock.recv(2)
                port = struct.unpack("!H", port_data)[0]
                raw_addr = bytes([ADDR_IPV4]) + addr_data + port_data
            elif addr_type == ADDR_DOMAIN:
                dlen = client_sock.recv(1)[0]
                domain = client_sock.recv(dlen)
                host = domain.decode("utf-8")
                port_data = client_sock.recv(2)
                port = struct.unpack("!H", port_data)[0]
                raw_addr = bytes([ADDR_DOMAIN, dlen]) + domain + port_data
            elif addr_type == ADDR_IPV6:
                addr_data = client_sock.recv(16)
                host = socket.inet_ntop(socket.AF_INET6, addr_data)
                port_data = client_sock.recv(2)
                port = struct.unpack("!H", port_data)[0]
                raw_addr = bytes([ADDR_IPV6]) + addr_data + port_data
            else:
                client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return None

            return host, port, raw_addr

        except Exception as e:
            print_debug(f"SOCKS5 handshake error: {e}")
            return None

    def _socks5_reply(self, client_sock, status):
        """Send SOCKS5 reply to client."""
        # Map proxy status to SOCKS5 reply codes
        socks_status = {
            STATUS_OK: 0x00,  # succeeded
            STATUS_REFUSED: 0x05,  # connection refused
            STATUS_UNREACHABLE: 0x04,  # host unreachable
            STATUS_TIMEOUT: 0x06,  # TTL expired (closest to timeout)
            STATUS_DNS_FAIL: 0x04,  # host unreachable
        }.get(
            status, 0x01
        )  # general failure

        reply = struct.pack("!BBBB", 0x05, socks_status, 0x00, 0x01)
        reply += b"\x00\x00\x00\x00\x00\x00"  # bind addr + port
        try:
            client_sock.sendall(reply)
        except Exception:
            pass

    # ── Client Handling ──────────────────────────────────────────────────

    def _handle_socks_client(self, client_sock, client_addr):
        """Handle one SOCKS5 client connection."""
        result = self._socks5_handshake(client_sock)
        if result is None:
            client_sock.close()
            return

        host, port, raw_addr = result

        # Assign channel ID
        with self.channel_lock:
            channel_id = self.next_channel_id
            self.next_channel_id += 1
            self.channels[channel_id] = client_sock
            event = threading.Event()
            self._connect_events[channel_id] = event

        if self.show_tunnel_logs:
            print_info(f"Tunnel ch={channel_id} -> {host}:{port}")

        # Send CONNECT_REQ to proxy binary
        if not self._send_frame(CONNECT_REQ, channel_id, raw_addr):
            if self.show_tunnel_logs:
                print_bad(f"Tunnel ch={channel_id} failed: pipe write error")
            self._socks5_reply(client_sock, STATUS_UNREACHABLE)
            self._cleanup_channel(channel_id)
            return

        # Wait for CONNECT_RESP (timeout 10s)
        if not event.wait(timeout=10):
            if self.show_tunnel_logs:
                print_bad(f"Tunnel ch={channel_id} -> {host}:{port} timed out")
            self._socks5_reply(client_sock, STATUS_TIMEOUT)
            self._cleanup_channel(channel_id)
            return

        status = self._connect_results.pop(channel_id, STATUS_UNREACHABLE)
        self._connect_events.pop(channel_id, None)

        # Send SOCKS5 reply
        self._socks5_reply(client_sock, status)

        if status != STATUS_OK:
            status_names = {
                STATUS_REFUSED: "refused",
                STATUS_UNREACHABLE: "unreachable",
                STATUS_TIMEOUT: "timeout",
                STATUS_DNS_FAIL: "DNS failure",
            }
            if self.show_tunnel_logs:
                print_bad(
                    f"Tunnel ch={channel_id} -> {host}:{port} failed: {status_names.get(status, 'unknown')}"
                )
            self._cleanup_channel(channel_id)
            return

        if self.show_tunnel_logs:
            print_good(f"Tunnel ch={channel_id} -> {host}:{port} established")

        # Start relay: read from SOCKS client → send DATA frames to proxy
        threading.Thread(
            target=self._client_to_pipe_relay,
            args=(channel_id, client_sock),
            daemon=True,
        ).start()

    def _client_to_pipe_relay(self, channel_id, client_sock):
        """Relay data from SOCKS client socket to pipe."""
        try:
            while self.running:
                try:
                    data = client_sock.recv(8192)
                except (ConnectionResetError, OSError):
                    break
                if not data:
                    break
                if not self._send_frame(DATA, channel_id, data):
                    break
        except Exception:
            pass
        finally:
            # Send CLOSE frame and clean up
            self._send_frame(CLOSE, channel_id, b"\x00")
            self._cleanup_channel(channel_id)

    def _cleanup_channel(self, channel_id):
        """Close and remove a channel."""
        with self.channel_lock:
            sock = self.channels.pop(channel_id, None)
            self._connect_events.pop(channel_id, None)
            self._connect_results.pop(channel_id, None)
        if sock:
            try:
                sock.close()
            except Exception:
                pass
            print_debug(f"Tunnel ch={channel_id} closed (active: {len(self.channels)})")

    # ── Pipe Reader ──────────────────────────────────────────────────────

    def _drain_write_queue(self):
        """Send all queued frames to the pipe. Called from the reader thread only."""
        while not self._write_queue.empty():
            try:
                data = self._write_queue.get_nowait()
                self.conn.writeFile(self.pipe_tid, self.pipe_fid, data, 0)
            except queue.Empty:
                break
            except Exception as e:
                print_debug(f"Pipe write error: {e}")
                break

    def _pipe_reader_loop(self):
        """Single pipe I/O thread: read frames, drain write queue between reads.

        The C++ proxy sends KEEPALIVE frames every 200ms which unblocks
        the readFile call. Between reads, we drain any queued writes.
        This avoids the SMB session deadlock from concurrent read/write.
        """
        while self.running:
            # Drain any queued writes before blocking on read
            self._drain_write_queue()

            msg_type, channel_id, payload = self._read_frame()
            if msg_type is None:
                if self.running:
                    print_warning("Proxy pipe connection lost — proxy process may have crashed")
                    print_info("Rebuild with 'proxy build --debug' for target-side logs")
                break

            if msg_type == DATA:
                with self.channel_lock:
                    sock = self.channels.get(channel_id)
                if sock:
                    try:
                        sock.sendall(payload)
                    except Exception:
                        self._cleanup_channel(channel_id)

            elif msg_type == CLOSE:
                self._cleanup_channel(channel_id)

            elif msg_type == CONNECT_RESP:
                status = payload[0] if payload else STATUS_UNREACHABLE
                self._connect_results[channel_id] = status
                event = self._connect_events.get(channel_id)
                if event:
                    event.set()

            elif msg_type == KEEPALIVE:
                pass  # ignore keepalive responses

        self.running = False

    # ── Server Lifecycle ─────────────────────────────────────────────────

    def start(self):
        """Start the SOCKS5 server and pipe reader."""
        self.running = True

        # Start pipe reader thread
        self._pipe_thread = threading.Thread(target=self._pipe_reader_loop, daemon=True)
        self._pipe_thread.start()

        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)
        self.server_socket.bind((self.bind_host, self.bind_port))
        self.server_socket.listen(5)

        print_good(f"SOCKS5 proxy listening on {self.bind_host}:{self.bind_port}")
        print_info(
            f"Configure clients: proxychains or --proxy socks5://{self.bind_host}:{self.bind_port}"
        )
        print_info("Type 'stop' or Ctrl+C to disconnect")

        # Accept loop
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _accept_loop(self):
        """Accept SOCKS5 client connections."""
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                threading.Thread(
                    target=self._handle_socks_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    print_debug("Accept error")
                break

    def stop(self):
        """Shutdown the proxy."""
        self.running = False

        # Send SHUTDOWN to proxy binary (best-effort)
        try:
            self._send_frame(SHUTDOWN, 0)
        except Exception:
            pass

        # Close all channels
        with self.channel_lock:
            for cid, sock in list(self.channels.items()):
                try:
                    sock.close()
                except Exception:
                    pass
            self.channels.clear()

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

        # Wait briefly for pipe reader thread to exit, then move on
        # The reader may be blocked on readFile — it will unblock when
        # the pipe is closed by the caller after stop() returns
        if hasattr(self, "_pipe_thread") and self._pipe_thread.is_alive():
            self._pipe_thread.join(timeout=2)

        print_info("SOCKS5 proxy stopped")

    @property
    def active_channels(self):
        return len(self.channels)
