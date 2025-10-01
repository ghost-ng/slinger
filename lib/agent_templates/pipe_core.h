#pragma once
#include "obfuscation.h"
#include <string>
#include <vector>
#include <memory>

// Cross-platform compatibility layer
#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <cstring>
    #include <errno.h>
#endif

namespace obf = obfuscated;

// Obfuscated pipe-related strings (cross-platform)
#ifdef _WIN32
constexpr auto PIPE_PREFIX = OBF_STRING("\\\\.\\pipe\\");
#else
constexpr auto PIPE_PREFIX = OBF_STRING("/tmp/");
#endif
constexpr auto AGENT_PIPE_NAME = OBF_STRING("slinger_agent_");
constexpr auto HANDSHAKE_MSG = OBF_STRING("SLINGER_READY");
constexpr auto ACK_MSG = OBF_STRING("ACK");
constexpr auto CMD_PREFIX = OBF_STRING("CMD:");
constexpr auto RESP_PREFIX = OBF_STRING("RESP:");
constexpr auto EXIT_CMD = OBF_STRING("EXIT");

// Command and response structure
struct PipeMessage {
    uint32_t length;
    uint32_t type;
    std::vector<char> data;

    enum MessageType {
        COMMAND = 0x1001,
        RESPONSE = 0x1002,
        HANDSHAKE = 0x1003,
        HEARTBEAT = 0x1004
    };
};

class PipeCore {
private:
#ifdef _WIN32
    HANDLE pipe_handle;
#else
    int socket_fd;
    int client_fd;
    struct sockaddr_un server_addr;
#endif
    std::string pipe_name;
    bool is_connected;
    obf::XOREncoder encoder;

    // Obfuscated method names
    bool OBF_FUNC_NAME(create_named_pipe)(const std::string& name);
    bool OBF_FUNC_NAME(connect_to_pipe)(const std::string& name);
#ifdef _WIN32
    bool OBF_FUNC_NAME(write_raw_data)(const void* data, DWORD size);
    bool OBF_FUNC_NAME(read_raw_data)(void* buffer, DWORD size, DWORD* bytes_read);
#else
    bool OBF_FUNC_NAME(write_raw_data)(const void* data, size_t size);
    bool OBF_FUNC_NAME(read_raw_data)(void* buffer, size_t size, size_t* bytes_read);
#endif

public:
    PipeCore();
    ~PipeCore();

    // Main interface methods
    bool initialize(const std::string& base_name);
    bool wait_for_connection();
    bool send_message(const PipeMessage& message);
    bool receive_message(PipeMessage& message);
    std::string read_command();
    bool send_response(const std::string& response);
    void disconnect_client();
    void cleanup();
    bool is_pipe_connected() const { return is_connected; }
};

// Implementation
PipeCore::PipeCore() :
#ifdef _WIN32
    pipe_handle(INVALID_HANDLE_VALUE),
#else
    socket_fd(-1), client_fd(-1),
#endif
    is_connected(false),
    encoder(obf::compile_seed()) {  // Use deterministic seed for XOR key
    obf::insert_junk_code();
#ifdef POSIX_BUILD
    memset(&server_addr, 0, sizeof(server_addr));
#endif
}

PipeCore::~PipeCore() {
    cleanup();
}

bool PipeCore::OBF_FUNC_NAME(create_named_pipe)(const std::string& name) {
    obf::insert_junk_code();

#ifdef _WIN32
    auto full_name = PIPE_PREFIX.decrypt() + name;
    obf::StackString<256> pipe_path(full_name.c_str());

    pipe_handle = CreateNamedPipeA(
        pipe_path.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, // Allow multiple connection attempts
        4096, // Out buffer size
        4096, // In buffer size
        0, // Default timeout
        NULL // Security attributes
    );

    return pipe_handle != INVALID_HANDLE_VALUE;
#else
    // Linux stub - create a simple socket for testing
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd == -1) return false;

    auto full_name = PIPE_PREFIX.decrypt() + name;
    strncpy(server_addr.sun_path, full_name.c_str(), sizeof(server_addr.sun_path) - 1);
    server_addr.sun_family = AF_UNIX;

    // Remove existing socket file
    unlink(full_name.c_str());

    // Bind socket
    if (bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    // Listen for connections
    if (listen(socket_fd, 1) == -1) {
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    return true;
#endif
}

bool PipeCore::initialize(const std::string& base_name) {
    if (!obf::check_timing()) return false;

    // Use custom pipe name if defined, otherwise generate unique pipe name
    #ifdef CUSTOM_PIPE_NAME
        pipe_name = std::string(CUSTOM_PIPE_NAME);
    #else
        // Generate unique pipe name with timestamp and suffix
        #ifdef _WIN32
            auto timestamp = std::to_string(GetTickCount64());
        #else
            auto timestamp = std::to_string(time(nullptr));
        #endif
        auto unique_suffix = std::to_string(obf::random_seed() % 9999);
        pipe_name = base_name + timestamp + "_" + unique_suffix;
    #endif

    return OBF_FUNC_NAME(create_named_pipe)(pipe_name);
}

bool PipeCore::wait_for_connection() {
#ifdef _WIN32
    if (pipe_handle == INVALID_HANDLE_VALUE) return false;

    obf::insert_junk_code();

    BOOL connected = ConnectNamedPipe(pipe_handle, NULL);
    DWORD error = GetLastError();
    if (!connected && error != ERROR_PIPE_CONNECTED) {
        // Log error for debugging (in production, this would be silent)
        // Common errors: ERROR_PIPE_LISTENING (231), ERROR_NO_DATA (232)
        if (error == ERROR_PIPE_LISTENING) {
            // Pipe is in listening state, this is actually OK
            connected = TRUE;
        } else {
            return false;
        }
    }

    is_connected = true;

    // Send handshake
    auto handshake = HANDSHAKE_MSG.decrypt();
    return send_response(handshake);
#else
    if (socket_fd == -1) return false;

    obf::insert_junk_code();

    // Accept connection
    socklen_t len = sizeof(server_addr);
    client_fd = accept(socket_fd, (struct sockaddr*)&server_addr, &len);
    if (client_fd == -1) return false;

    is_connected = true;

    // Send handshake
    auto handshake = HANDSHAKE_MSG.decrypt();
    return send_response(handshake);
#endif
}

#ifdef _WIN32
bool PipeCore::OBF_FUNC_NAME(write_raw_data)(const void* data, DWORD size) {
    if (!is_connected) return false;

    DWORD bytes_written = 0;
    BOOL result = WriteFile(pipe_handle, data, size, &bytes_written, NULL);
    return result && bytes_written == size;
}

bool PipeCore::OBF_FUNC_NAME(read_raw_data)(void* buffer, DWORD size, DWORD* bytes_read) {
    if (!is_connected) return false;

    // Use PeekNamedPipe to check if data is available (non-blocking check)
    DWORD bytes_available = 0;
    if (!PeekNamedPipe(pipe_handle, NULL, 0, NULL, &bytes_available, NULL)) {
        // Connection broken
        return false;
    }

    // If no data available, wait briefly and check again (simple timeout)
    if (bytes_available == 0) {
        Sleep(100); // Wait 100ms
        if (!PeekNamedPipe(pipe_handle, NULL, 0, NULL, &bytes_available, NULL)) {
            return false;
        }
        if (bytes_available == 0) {
            *bytes_read = 0;
            return false; // Timeout - no data
        }
    }

    return ReadFile(pipe_handle, buffer, size, bytes_read, NULL);
}
#else
bool PipeCore::OBF_FUNC_NAME(write_raw_data)(const void* data, size_t size) {
    if (!is_connected) return false;

    ssize_t bytes_written = write(client_fd, data, size);
    return bytes_written == (ssize_t)size;
}

bool PipeCore::OBF_FUNC_NAME(read_raw_data)(void* buffer, size_t size, size_t* bytes_read) {
    if (!is_connected) return false;

    ssize_t result = read(client_fd, buffer, size);
    if (result >= 0) {
        *bytes_read = result;
        return true;
    }
    return false;
}
#endif

bool PipeCore::send_message(const PipeMessage& message) {
    if (!is_connected) return false;

    obf::insert_junk_code();

    // Send header
    uint32_t header[2] = {message.length, message.type};
    if (!OBF_FUNC_NAME(write_raw_data)(header, sizeof(header))) {
        return false;
    }

    // Send data
    if (message.length > 0) {
        return OBF_FUNC_NAME(write_raw_data)(message.data.data(), message.length);
    }

    return true;
}

bool PipeCore::receive_message(PipeMessage& message) {
    if (!is_connected) return false;

    // Read header
    uint32_t header[2];
#ifdef _WIN32
    DWORD bytes_read = 0;
#else
    size_t bytes_read = 0;
#endif
    if (!OBF_FUNC_NAME(read_raw_data)(header, sizeof(header), &bytes_read) ||
        bytes_read != sizeof(header)) {
        return false;
    }

    message.length = header[0];
    message.type = header[1];

    // Read data
    if (message.length > 0) {
        message.data.resize(message.length);
        if (!OBF_FUNC_NAME(read_raw_data)(message.data.data(), message.length, &bytes_read) ||
            bytes_read != message.length) {
            return false;
        }
    }

    return true;
}

std::string PipeCore::read_command() {
    if (!is_connected) return "";

    PipeMessage message;
    if (!receive_message(message)) {
        return "";
    }

    if (message.type != PipeMessage::COMMAND) {
        return "";
    }

    std::string command(message.data.begin(), message.data.end());
    return encoder.decode(command);
}

bool PipeCore::send_response(const std::string& response) {
    if (!is_connected) return false;

    auto encoded_response = encoder.encode(response);

    PipeMessage message;
    message.type = PipeMessage::RESPONSE;
    message.length = static_cast<uint32_t>(encoded_response.length());
    message.data.assign(encoded_response.begin(), encoded_response.end());

    return send_message(message);
}

void PipeCore::disconnect_client() {
#ifdef _WIN32
    if (pipe_handle != INVALID_HANDLE_VALUE && is_connected) {
        DisconnectNamedPipe(pipe_handle);
        is_connected = false;
    }
#else
    if (client_fd != -1) {
        close(client_fd);
        client_fd = -1;
        is_connected = false;
    }
#endif
}

void PipeCore::cleanup() {
#ifdef _WIN32
    if (pipe_handle != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(pipe_handle);
        CloseHandle(pipe_handle);
        pipe_handle = INVALID_HANDLE_VALUE;
    }
#else
    if (client_fd != -1) {
        close(client_fd);
        client_fd = -1;
    }
    if (socket_fd != -1) {
        close(socket_fd);
        socket_fd = -1;
        // Remove socket file
        if (!pipe_name.empty()) {
            auto full_name = PIPE_PREFIX.decrypt() + pipe_name;
            unlink(full_name.c_str());
        }
    }
#endif
    is_connected = false;

    // Clear sensitive data
    pipe_name.clear();
    obf::insert_junk_code();
}
