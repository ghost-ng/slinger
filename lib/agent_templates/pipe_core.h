#pragma once
#include "obfuscation.h"
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

namespace obf = obfuscated;

// Obfuscated pipe-related strings
constexpr auto PIPE_PREFIX = OBF_STRING("\\\\.\\pipe\\");
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
    HANDLE pipe_handle;
    std::string pipe_name;
    bool is_connected;
    obf::XOREncoder encoder;

    // Obfuscated method names
    bool OBF_FUNC_NAME(create_named_pipe)(const std::string& name);
    bool OBF_FUNC_NAME(connect_to_pipe)(const std::string& name);
    bool OBF_FUNC_NAME(write_raw_data)(const void* data, DWORD size);
    bool OBF_FUNC_NAME(read_raw_data)(void* buffer, DWORD size, DWORD* bytes_read);

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
    void cleanup();
    bool is_pipe_connected() const { return is_connected; }
};

// Implementation
PipeCore::PipeCore() : pipe_handle(INVALID_HANDLE_VALUE), is_connected(false) {
    obf::insert_junk_code();
}

PipeCore::~PipeCore() {
    cleanup();
}

bool PipeCore::OBF_FUNC_NAME(create_named_pipe)(const std::string& name) {
    obf::insert_junk_code();

    auto full_name = PIPE_PREFIX.decrypt() + name;
    obf::StackString<256> pipe_path(full_name.c_str());

    pipe_handle = CreateNamedPipeA(
        pipe_path.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, // Max instances
        4096, // Out buffer size
        4096, // In buffer size
        0, // Default timeout
        NULL // Security attributes
    );

    return pipe_handle != INVALID_HANDLE_VALUE;
}

bool PipeCore::initialize(const std::string& base_name) {
    if (!obf::check_timing()) return false;

    // Generate unique pipe name
    auto timestamp = std::to_string(GetTickCount64());
    auto unique_suffix = std::to_string(obf::random_seed() % 9999);
    pipe_name = base_name + timestamp + "_" + unique_suffix;

    return OBF_FUNC_NAME(create_named_pipe)(pipe_name);
}

bool PipeCore::wait_for_connection() {
    if (pipe_handle == INVALID_HANDLE_VALUE) return false;

    obf::insert_junk_code();

    BOOL connected = ConnectNamedPipe(pipe_handle, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        return false;
    }

    is_connected = true;

    // Send handshake
    auto handshake = HANDSHAKE_MSG.decrypt();
    return send_response(handshake);
}

bool PipeCore::OBF_FUNC_NAME(write_raw_data)(const void* data, DWORD size) {
    if (!is_connected) return false;

    DWORD bytes_written = 0;
    BOOL result = WriteFile(pipe_handle, data, size, &bytes_written, NULL);
    return result && bytes_written == size;
}

bool PipeCore::OBF_FUNC_NAME(read_raw_data)(void* buffer, DWORD size, DWORD* bytes_read) {
    if (!is_connected) return false;

    return ReadFile(pipe_handle, buffer, size, bytes_read, NULL);
}

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
    DWORD bytes_read = 0;
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

void PipeCore::cleanup() {
    if (pipe_handle != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(pipe_handle);
        CloseHandle(pipe_handle);
        pipe_handle = INVALID_HANDLE_VALUE;
    }
    is_connected = false;

    // Clear sensitive data
    pipe_name.clear();
    obf::insert_junk_code();
}
