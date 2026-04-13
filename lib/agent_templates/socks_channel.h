#pragma once

// winsock2.h MUST be included before windows.h to avoid conflicts
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    typedef int SOCKET;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)
    #define closesocket close
#endif

#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdint>

// ── Multiplexed proxy protocol ──────────────────────────────────────────────

// Message type constants (not in struct to avoid OBF_FUNC_NAME issues)
static const uint32_t PROXY_MSG_CONNECT_REQ  = 0x2001;
static const uint32_t PROXY_MSG_CONNECT_RESP = 0x2002;
static const uint32_t PROXY_MSG_DATA         = 0x2003;
static const uint32_t PROXY_MSG_CLOSE        = 0x2004;
static const uint32_t PROXY_MSG_KEEPALIVE    = 0x2005;
static const uint32_t PROXY_MSG_SHUTDOWN     = 0x2006;

// Connect status codes (prefixed to avoid Windows macro conflicts)
static const uint8_t PROXY_STATUS_OK          = 0x00;
static const uint8_t PROXY_STATUS_REFUSED     = 0x01;
static const uint8_t PROXY_STATUS_UNREACHABLE = 0x02;
static const uint8_t PROXY_STATUS_TIMEDOUT    = 0x03;
static const uint8_t PROXY_STATUS_DNS_FAIL    = 0x04;

// Address types
static const uint8_t PROXY_ADDR_IPV4   = 0x01;
static const uint8_t PROXY_ADDR_DOMAIN = 0x03;
static const uint8_t PROXY_ADDR_IPV6   = 0x04;

struct ProxyFrame {
    uint32_t length;      // total payload length
    uint32_t msg_type;    // message type enum
    uint32_t channel_id;  // tunnel channel identifier
    std::vector<uint8_t> payload;

    // Serialize frame to wire format (header + payload)
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;
        uint32_t payload_len = static_cast<uint32_t>(payload.size());
        buf.resize(12 + payload_len);
        memcpy(&buf[0], &payload_len, 4);
        memcpy(&buf[4], &msg_type, 4);
        memcpy(&buf[8], &channel_id, 4);
        if (payload_len > 0) {
            memcpy(&buf[12], payload.data(), payload_len);
        }
        return buf;
    }
};

// ── Channel: one SOCKS tunnel ───────────────────────────────────────────────

struct Channel {
    uint32_t id;
    SOCKET tcp_socket;
    std::string target_host;
    uint16_t target_port;
    bool connected;

    Channel() : id(0), tcp_socket(INVALID_SOCKET), target_port(0), connected(false) {}
};

// ── Channel Manager ─────────────────────────────────────────────────────────

class ChannelManager {
private:
    std::unordered_map<uint32_t, Channel> channels;

public:
    ChannelManager() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    }

    ~ChannelManager() {
        close_all();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    // Open a TCP connection for a channel
    uint8_t open_channel(uint32_t id, const std::string& host, uint16_t port) {
        DEBUG_LOG_CAT("CHAN", "Opening channel " + std::to_string(id) + " -> " + host + ":" + std::to_string(port));

        Channel ch;
        ch.id = id;
        ch.target_host = host;
        ch.target_port = port;

        // Resolve hostname
        struct addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        std::string port_str = std::to_string(port);
        int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
        if (rc != 0 || result == nullptr) {
            DEBUG_LOG_CAT("CHAN", "DNS resolution failed for " + host);
            return PROXY_STATUS_DNS_FAIL;
        }

        // Create socket and connect
        ch.tcp_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (ch.tcp_socket == INVALID_SOCKET) {
            freeaddrinfo(result);
            return PROXY_STATUS_UNREACHABLE;
        }

        // Set connect timeout (5 seconds)
#ifdef _WIN32
        DWORD timeout_ms = 5000;
        setsockopt(ch.tcp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
        setsockopt(ch.tcp_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
#else
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(ch.tcp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(ch.tcp_socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

        rc = connect(ch.tcp_socket, result->ai_addr, (int)result->ai_addrlen);
        freeaddrinfo(result);

        if (rc == SOCKET_ERROR) {
#ifdef _WIN32
            int err = WSAGetLastError();
            closesocket(ch.tcp_socket);
            if (err == WSAECONNREFUSED) return PROXY_STATUS_REFUSED;
            if (err == WSAETIMEDOUT) return PROXY_STATUS_TIMEDOUT;
#else
            int err = errno;
            closesocket(ch.tcp_socket);
            if (err == ECONNREFUSED) return PROXY_STATUS_REFUSED;
            if (err == ETIMEDOUT) return PROXY_STATUS_TIMEDOUT;
#endif
            return PROXY_STATUS_UNREACHABLE;
        }

        // Set non-blocking for relay
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(ch.tcp_socket, FIONBIO, &mode);
#else
        int flags = fcntl(ch.tcp_socket, F_GETFL, 0);
        fcntl(ch.tcp_socket, F_SETFL, flags | O_NONBLOCK);
#endif

        ch.connected = true;
        channels[id] = ch;

        DEBUG_LOG_CAT("CHAN", "Channel " + std::to_string(id) + " connected");
        return PROXY_STATUS_OK;
    }

    void close_channel(uint32_t id) {
        auto it = channels.find(id);
        if (it != channels.end()) {
            if (it->second.tcp_socket != INVALID_SOCKET) {
                closesocket(it->second.tcp_socket);
            }
            DEBUG_LOG_CAT("CHAN", "Channel " + std::to_string(id) + " closed");
            channels.erase(it);
        }
    }

    Channel* get_channel(uint32_t id) {
        auto it = channels.find(id);
        return (it != channels.end()) ? &it->second : nullptr;
    }

    // Collect all active TCP sockets for polling
    void get_all_sockets(std::vector<SOCKET>& out, std::vector<uint32_t>& ids) {
        out.clear();
        ids.clear();
        for (auto& pair : channels) {
            if (pair.second.connected && pair.second.tcp_socket != INVALID_SOCKET) {
                out.push_back(pair.second.tcp_socket);
                ids.push_back(pair.first);
            }
        }
    }

    size_t active_count() const {
        return channels.size();
    }

    void close_all() {
        for (auto& pair : channels) {
            if (pair.second.tcp_socket != INVALID_SOCKET) {
                closesocket(pair.second.tcp_socket);
            }
        }
        channels.clear();
    }

    // Send data to a channel's TCP socket
    int send_to_channel(uint32_t id, const uint8_t* data, size_t len) {
        auto* ch = get_channel(id);
        if (!ch || !ch->connected) return -1;
        return send(ch->tcp_socket, (const char*)data, (int)len, 0);
    }

    // Read data from a channel's TCP socket (non-blocking)
    int recv_from_channel(uint32_t id, uint8_t* buf, size_t max_len) {
        auto* ch = get_channel(id);
        if (!ch || !ch->connected) return -1;
        int n = recv(ch->tcp_socket, (char*)buf, (int)max_len, 0);
#ifdef _WIN32
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) return 0;
#else
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
#endif
        return n;
    }
};
