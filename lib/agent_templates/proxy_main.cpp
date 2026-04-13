// Slinger SOCKS5 Proxy — Lightweight named pipe tunnel relay
// Listens on a named pipe, accepts multiplexed channel requests,
// opens outbound TCP connections, relays data bidirectionally.
// No command execution — single purpose: network pivoting.

#include <string>
#include <vector>
#include <ctime>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/time.h>
    #include <thread>
    #include <chrono>
#endif

// Debug logging (conditionally compiled — same pattern as agent)
#ifdef DEBUG_MODE
#include <fstream>
#include <sstream>
class DebugLogger {
private:
    std::ofstream log_file;
    bool enabled;
    std::string get_timestamp() {
#ifdef _WIN32
        SYSTEMTIME st; GetLocalTime(&st);
        char buf[64];
        sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return std::string(buf);
#else
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        char buf[64]; std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        char full[80]; sprintf(full, "%s.%03ld", buf, ms.count());
        return std::string(full);
#endif
    }
public:
    DebugLogger() : enabled(false) {
#ifdef _WIN32
        char p[MAX_PATH]; GetModuleFileNameA(NULL, p, MAX_PATH);
        std::string d(p); auto pos = d.find_last_of("\\/");
        if (pos != std::string::npos) d = d.substr(0, pos);
        std::string lp = d + "\\slinger_proxy_debug.log";
#else
        std::string lp = "./slinger_proxy_debug.log";
#endif
        log_file.open(lp, std::ios::out | std::ios::app);
        if (log_file.is_open()) { enabled = true; log("=== Slinger Proxy Debug Log ==="); }
    }
    ~DebugLogger() { if (enabled) { log("Proxy shutting down"); log_file.close(); } }
    void log(const std::string& msg) {
        if (enabled && log_file.is_open()) { log_file << "[" << get_timestamp() << "] " << msg << std::endl; log_file.flush(); }
    }
    void log(const std::string& cat, const std::string& msg) {
        if (enabled && log_file.is_open()) { log_file << "[" << get_timestamp() << "][" << cat << "] " << msg << std::endl; log_file.flush(); }
    }
};
static DebugLogger g_debug_log;
#define DEBUG_LOG(msg) g_debug_log.log(msg)
#define DEBUG_LOG_CAT(cat, msg) g_debug_log.log(cat, msg)
#else
#define DEBUG_LOG(msg)
#define DEBUG_LOG_CAT(cat, msg)
#endif

// socks_channel.h MUST come first — it includes winsock2.h before windows.h
#include "socks_channel.h"
#include "obfuscation.h"
#include "pipe_core.h"

namespace obf = obfuscated;

// Obfuscated function names
#define PROXY_MAIN OBF_FUNC_NAME(proxy_main_entry)
#define PROXY_LOOP OBF_FUNC_NAME(proxy_event_loop)
#define PROXY_HANDLE_FRAME OBF_FUNC_NAME(proxy_handle_frame)

// Obfuscated strings
constexpr auto PROXY_PIPE_NAME = OBF_STRING("\\\\.\\pipe\\slinger_proxy_");

class SlingerProxy {
private:
    PipeCore pipe;
    ChannelManager channels;
    bool running;

    // Raw pipe I/O wrappers (bypass PipeCore's message framing — we use our own)
    bool OBF_FUNC_NAME(write_pipe_raw)(const void* data, size_t size) {
#ifdef _WIN32
        DWORD written = 0;
        // Access pipe_handle via PipeCore's public interface isn't available,
        // so we use send_response/read_command for auth, then raw after.
        // Actually, we need direct handle access. Use PipeCore's internal methods.
        // PipeCore exposes send_message/receive_message which add framing.
        // For our protocol we need raw access. We'll use the same write_raw_data pattern.
        // Since pipe_core.h methods are private with OBF names, we write through send_response
        // which just does write_raw_data underneath.
        //
        // Better approach: after auth handshake, we take over with raw pipe I/O using
        // the Windows API directly on the pipe handle. We get the handle from PipeCore
        // by adding a getter, or we just open the pipe ourselves after PipeCore creates it.
        //
        // Simplest: PipeCore creates the pipe and does auth. Then we read/write raw.
        // We need to expose the pipe handle. Let's add a method.
        return false; // placeholder — see actual implementation below
#else
        return false;
#endif
    }

    // Direct pipe handle for raw I/O after auth
    // We extract this from PipeCore after initialization
#ifdef _WIN32
    HANDLE raw_pipe_handle;
#else
    int raw_pipe_fd;
#endif

    bool OBF_FUNC_NAME(raw_write)(const void* data, uint32_t size) {
#ifdef _WIN32
        DWORD written = 0;
        return WriteFile(raw_pipe_handle, data, size, &written, NULL) && written == size;
#else
        return write(raw_pipe_fd, data, size) == (ssize_t)size;
#endif
    }

    bool pipe_broken;

    // Non-blocking read from pipe — returns bytes read, 0 if no data, -1 on error
    int OBF_FUNC_NAME(raw_read_nb)(void* buf, uint32_t max_size) {
#ifdef _WIN32
        DWORD avail = 0;
        if (!PeekNamedPipe(raw_pipe_handle, NULL, 0, NULL, &avail, NULL)) {
            pipe_broken = true;
            return -1;
        }
        if (avail == 0) return 0;
        DWORD to_read = (avail < max_size) ? avail : max_size;
        DWORD got = 0;
        if (!ReadFile(raw_pipe_handle, buf, to_read, &got, NULL)) {
            pipe_broken = true;
            return -1;
        }
        return (int)got;
#else
        int n = read(raw_pipe_fd, buf, max_size);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n <= 0) pipe_broken = true;
        return n;
#endif
    }

    // Blocking read of exact N bytes from pipe
    bool OBF_FUNC_NAME(raw_read_exact)(void* buf, uint32_t size) {
        uint32_t total = 0;
        uint8_t* p = (uint8_t*)buf;
        while (total < size) {
#ifdef _WIN32
            // Wait for data with timeout
            DWORD avail = 0;
            int wait_ms = 0;
            while (avail == 0 && wait_ms < 30000) {
                if (!PeekNamedPipe(raw_pipe_handle, NULL, 0, NULL, &avail, NULL)) return false;
                if (avail == 0) { Sleep(10); wait_ms += 10; }
            }
            if (avail == 0) return false;
            DWORD got = 0;
            DWORD want = size - total;
            if (!ReadFile(raw_pipe_handle, p + total, want, &got, NULL) || got == 0) return false;
            total += got;
#else
            ssize_t n = read(raw_pipe_fd, p + total, size - total);
            if (n <= 0) return false;
            total += n;
#endif
        }
        return true;
    }

    // Send a proxy frame over the pipe
    bool OBF_FUNC_NAME(send_frame)(const ProxyFrame& frame) {
        auto data = frame.serialize();
        return OBF_FUNC_NAME(raw_write)(data.data(), (uint32_t)data.size());
    }

    // Read one proxy frame from the pipe (non-blocking, returns false if no data)
    bool OBF_FUNC_NAME(read_frame_nb)(ProxyFrame& frame) {
        // Peek for header
        uint8_t hdr[12];
        int n = OBF_FUNC_NAME(raw_read_nb)(hdr, 12);
        if (n <= 0) return false;
        if (n < 12) {
            // Got partial header — read the rest blocking
            if (!OBF_FUNC_NAME(raw_read_exact)(hdr + n, 12 - n)) return false;
        }

        memcpy(&frame.length, &hdr[0], 4);
        memcpy(&frame.msg_type, &hdr[4], 4);
        memcpy(&frame.channel_id, &hdr[8], 4);

        // Sanity check
        if (frame.length > 65536) {
            DEBUG_LOG_CAT("PROTO", "Frame too large: " + std::to_string(frame.length));
            return false;
        }

        // Read payload
        frame.payload.resize(frame.length);
        if (frame.length > 0) {
            if (!OBF_FUNC_NAME(raw_read_exact)(frame.payload.data(), frame.length)) return false;
        }
        return true;
    }

    // Parse CONNECT_REQ payload → host + port
    bool OBF_FUNC_NAME(parse_connect_req)(const ProxyFrame& frame, std::string& host, uint16_t& port) {
        if (frame.payload.size() < 4) return false;
        const uint8_t* p = frame.payload.data();
        uint8_t addr_type = p[0];

        if (addr_type == PROXY_ADDR_IPV4) {
            if (frame.payload.size() < 7) return false;
            char ip[INET_ADDRSTRLEN];
            struct in_addr addr;
            memcpy(&addr, p + 1, 4);
            inet_ntop(AF_INET, &addr, ip, sizeof(ip));
            host = ip;
            memcpy(&port, p + 5, 2);
            port = ntohs(port);
        } else if (addr_type == PROXY_ADDR_DOMAIN) {
            uint8_t dlen = p[1];
            if (frame.payload.size() < (size_t)(2 + dlen + 2)) return false;
            host = std::string((char*)p + 2, dlen);
            memcpy(&port, p + 2 + dlen, 2);
            port = ntohs(port);
        } else if (addr_type == PROXY_ADDR_IPV6) {
            if (frame.payload.size() < 19) return false;
            char ip[INET6_ADDRSTRLEN];
            struct in6_addr addr;
            memcpy(&addr, p + 1, 16);
            inet_ntop(AF_INET6, &addr, ip, sizeof(ip));
            host = ip;
            memcpy(&port, p + 17, 2);
            port = ntohs(port);
        } else {
            return false;
        }
        return true;
    }

    // Handle one incoming frame from the pipe
    void OBF_FUNC_NAME(handle_frame)(const ProxyFrame& frame) {
        switch (frame.msg_type) {
            case PROXY_MSG_CONNECT_REQ: {
                std::string host;
                uint16_t port;
                if (!OBF_FUNC_NAME(parse_connect_req)(frame, host, port)) {
                    DEBUG_LOG_CAT("PROTO", "Bad CONNECT_REQ");
                    break;
                }
                DEBUG_LOG_CAT("PROXY", "CONNECT ch=" + std::to_string(frame.channel_id) +
                              " -> " + host + ":" + std::to_string(port));

                uint8_t status = channels.open_channel(frame.channel_id, host, port);

                // Send CONNECT_RESP
                ProxyFrame resp;
                resp.msg_type = PROXY_MSG_CONNECT_RESP;
                resp.channel_id = frame.channel_id;
                resp.payload = {status};
                OBF_FUNC_NAME(send_frame)(resp);
                break;
            }

            case PROXY_MSG_DATA: {
                if (frame.payload.empty()) break;
                int sent = channels.send_to_channel(
                    frame.channel_id, frame.payload.data(), frame.payload.size());
                if (sent < 0) {
                    // TCP socket dead — close channel
                    ProxyFrame close_frame;
                    close_frame.msg_type = PROXY_MSG_CLOSE;
                    close_frame.channel_id = frame.channel_id;
                    close_frame.payload = {0x01}; // error
                    OBF_FUNC_NAME(send_frame)(close_frame);
                    channels.close_channel(frame.channel_id);
                }
                break;
            }

            case PROXY_MSG_CLOSE: {
                channels.close_channel(frame.channel_id);
                break;
            }

            case PROXY_MSG_KEEPALIVE: {
                ProxyFrame pong;
                pong.msg_type = PROXY_MSG_KEEPALIVE;
                pong.channel_id = 0;
                OBF_FUNC_NAME(send_frame)(pong);
                break;
            }

            case PROXY_MSG_SHUTDOWN: {
                DEBUG_LOG_CAT("PROXY", "SHUTDOWN received");
                running = false;
                break;
            }
        }
    }

    // Main event loop — poll pipe + all TCP sockets
    void OBF_FUNC_NAME(event_loop)() {
        DEBUG_LOG_CAT("PROXY", "Entering event loop");
        pipe_broken = false;
        uint8_t tcp_buf[8192];

        // Send periodic keepalive frames so the Python reader unblocks
        // and can process queued writes (SMB serializes read/write on one socket)
#ifdef _WIN32
        DWORD last_keepalive = GetTickCount();
        const DWORD KEEPALIVE_MS = 200;
#else
        auto last_keepalive = std::chrono::steady_clock::now();
#endif

        while (running && !pipe_broken) {
            // 1. Check pipe for incoming frames (non-blocking)
            ProxyFrame frame;
            while (OBF_FUNC_NAME(read_frame_nb)(frame)) {
                OBF_FUNC_NAME(handle_frame)(frame);
                if (!running) return;
            }
            if (pipe_broken) {
                DEBUG_LOG_CAT("PROXY", "Pipe broken, exiting event loop");
                break;
            }

            // 2. Check all TCP sockets for data to relay back
            std::vector<SOCKET> sockets;
            std::vector<uint32_t> chan_ids;
            channels.get_all_sockets(sockets, chan_ids);

            for (size_t i = 0; i < sockets.size(); i++) {
                int n = channels.recv_from_channel(chan_ids[i], tcp_buf, sizeof(tcp_buf));
                if (n > 0) {
                    // Forward TCP data back through pipe
                    ProxyFrame data_frame;
                    data_frame.msg_type = PROXY_MSG_DATA;
                    data_frame.channel_id = chan_ids[i];
                    data_frame.payload.assign(tcp_buf, tcp_buf + n);
                    OBF_FUNC_NAME(send_frame)(data_frame);
                } else if (n < 0) {
                    // TCP connection closed or error
                    DEBUG_LOG_CAT("PROXY", "TCP closed for ch=" + std::to_string(chan_ids[i]));
                    ProxyFrame close_frame;
                    close_frame.msg_type = PROXY_MSG_CLOSE;
                    close_frame.channel_id = chan_ids[i];
                    close_frame.payload = {0x00}; // normal close
                    OBF_FUNC_NAME(send_frame)(close_frame);
                    channels.close_channel(chan_ids[i]);
                }
            }

            // 3. Send keepalive to unblock Python's readFile periodically
#ifdef _WIN32
            DWORD now = GetTickCount();
            if (now - last_keepalive >= KEEPALIVE_MS) {
                ProxyFrame ka;
                ka.msg_type = PROXY_MSG_KEEPALIVE;
                ka.channel_id = 0;
                OBF_FUNC_NAME(send_frame)(ka);
                last_keepalive = now;
            }
#else
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_keepalive).count();
            if (elapsed >= 200) {
                ProxyFrame ka;
                ka.msg_type = PROXY_MSG_KEEPALIVE;
                ka.channel_id = 0;
                OBF_FUNC_NAME(send_frame)(ka);
                last_keepalive = now;
            }
#endif

            // Brief sleep to avoid busy-wait (10ms)
#ifdef _WIN32
            Sleep(10);
#else
            usleep(10000);
#endif
        }

        // Cleanup — close all channels
        channels.close_all();
        DEBUG_LOG_CAT("PROXY", "Event loop exited");
    }

public:
    SlingerProxy() : running(false), pipe_broken(false) {
#ifdef _WIN32
        raw_pipe_handle = INVALID_HANDLE_VALUE;
#else
        raw_pipe_fd = -1;
#endif
        DEBUG_LOG_CAT("INIT", "SlingerProxy created");
    }

    int OBF_FUNC_NAME(run)() {
        DEBUG_LOG_CAT("MAIN", "Proxy starting");

        // Initialize pipe (reuse PipeCore for pipe creation + auth)
#ifdef AGENT_PASSPHRASE
        DEBUG_LOG_CAT("AUTH", "Passphrase authentication enabled");
        std::string pipe_base = "slinger_proxy_";
    #ifdef CUSTOM_PIPE_NAME
        // Pipe name is obfuscated at compile time via OBF_STRING
        // pipe_core.h's initialize() handles decryption internally
    #endif
        constexpr auto _obf_pass = OBF_STRING(AGENT_PASSPHRASE);
        auto _dec_pass = _obf_pass.decrypt();
        if (!pipe.initialize_with_passphrase(pipe_base, _dec_pass.c_str(), pipe_base.c_str())) {
            DEBUG_LOG_CAT("ERROR", "Failed to initialize pipe with auth");
            return 1;
        }
#else
        DEBUG_LOG_CAT("AUTH", "No passphrase — XOR encoding only");
        std::string pipe_base = "slinger_proxy_";
    #ifdef CUSTOM_PIPE_NAME
        // pipe_core.h's initialize() handles CUSTOM_PIPE_NAME via OBF_STRING
    #endif
        if (!pipe.initialize(pipe_base)) {
            DEBUG_LOG_CAT("ERROR", "Failed to initialize pipe");
            return 1;
        }
#endif

        // Outer loop: accept connections, run event loop, reconnect
        // The proxy stays alive and accepts multiple client sessions
        bool alive = true;
        while (alive) {
            DEBUG_LOG_CAT("PIPE", "Waiting for client connection");
            if (!pipe.wait_for_connection()) {
                DEBUG_LOG_CAT("PIPE", "Connection failed, retrying in 5s");
#ifdef _WIN32
                Sleep(5000);
#else
                sleep(5);
#endif
                continue;
            }

            DEBUG_LOG_CAT("PIPE", "Client connected");

            // Auth handshake
#ifdef AGENT_PASSPHRASE
            if (!pipe.perform_authentication()) {
                DEBUG_LOG_CAT("AUTH", "Auth failed, disconnecting");
                pipe.disconnect_client();
                continue;
            }
            DEBUG_LOG_CAT("AUTH", "Authenticated");
#endif

            // Get raw pipe handle for direct I/O after auth
            raw_pipe_handle = pipe.get_pipe_handle();

            DEBUG_LOG_CAT("PROXY", "Starting relay event loop");
            running = true;
            OBF_FUNC_NAME(event_loop)();

            // Event loop exited — client disconnected or sent SHUTDOWN
            pipe.disconnect_client();
            DEBUG_LOG_CAT("PROXY", "Client disconnected, ready for next connection");

            // If SHUTDOWN was received, exit completely
            if (!running) {
                DEBUG_LOG_CAT("PROXY", "SHUTDOWN received, exiting");
                alive = false;
            }
        }

        pipe.cleanup();
        DEBUG_LOG_CAT("MAIN", "Proxy exiting");
        return 0;
    }
};

// Obfuscated main with control flow obfuscation (same pattern as agent)
int OBF_FUNC_NAME(PROXY_MAIN)() {
    DEBUG_LOG("=== PROXY ENTRY POINT ===");
    volatile int flow = obf::random_seed() % 3;
    switch (flow) {
        case 0: goto run_proxy;
        case 1: goto alt_path;
        default: goto run_proxy;
    }
alt_path:
    { volatile int junk = obf::random_seed() * 0x1337; (void)junk; }
run_proxy:
    {
        SlingerProxy proxy;
        return proxy.OBF_FUNC_NAME(run)();
    }
}

int main() {
    DEBUG_LOG("=== BINARY STARTED ===");
    volatile int junk = obf::random_seed();
    volatile int junk2 = junk * 0x1337;
    (void)junk2;
    return OBF_FUNC_NAME(PROXY_MAIN)();
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    return main();
}
#endif
