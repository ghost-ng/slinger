# CMake configuration for polymorphic agent builds
cmake_minimum_required(VERSION 3.15)
project(SlingerAgent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_BITS 64)
    set(ARCH_SUFFIX "x64")
else()
    set(ARCH_BITS 32)
    set(ARCH_SUFFIX "x86")
endif()

# Compiler-specific optimizations and obfuscation
if(MSVC)
    # MSVC specific flags for obfuscation
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2 /Ob2 /GL /LTCG")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS- /Gy /Gw")
    # Remove debug information
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /DNDEBUG")
    # Link time optimization
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG /OPT:REF /OPT:ICF")
elseif(GNU)
    # GCC/MinGW specific flags
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -ffunction-sections -fdata-sections")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector -fno-exceptions")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -s")
endif()

# Source files
set(AGENT_SOURCES
    agent_main.cpp
    obfuscation.h
    pipe_core.h
    command_executor.h
)

# Create executable with obfuscated name
set(EXECUTABLE_NAME "slinger_agent_${ARCH_SUFFIX}")

# Add polymorphic build options
option(ENABLE_ENCRYPTION "Enable polymorphic encryption" ON)
option(RANDOMIZE_LAYOUT "Randomize code layout" ON)
option(OBFUSCATE_STRINGS "Obfuscate string literals" ON)

if(ENABLE_ENCRYPTION)
    add_definitions(-DENABLE_POLYMORPHIC_ENCRYPTION)
endif()

if(RANDOMIZE_LAYOUT)
    add_definitions(-DRANDOMIZE_CODE_LAYOUT)
endif()

if(OBFUSCATE_STRINGS)
    add_definitions(-DOBFUSCATE_ALL_STRINGS)
endif()

# Generate unique build ID for polymorphic encryption
string(TIMESTAMP BUILD_ID "%Y%m%d%H%M%S")
math(EXPR RANDOM_SEED "${BUILD_ID} % 65536")
add_definitions(-DBUILD_SEED=${RANDOM_SEED})

# Create the agent executable
add_executable(${EXECUTABLE_NAME} ${AGENT_SOURCES})

# Link required Windows libraries
if(WIN32)
    target_link_libraries(${EXECUTABLE_NAME} PRIVATE
        kernel32
        user32
        advapi32
        shell32
    )
endif()

# Set output directory
set_target_properties(${EXECUTABLE_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    OUTPUT_NAME "agent_${RANDOM_SEED}_${ARCH_SUFFIX}"
)

# Custom commands for polymorphic builds
add_custom_command(TARGET ${EXECUTABLE_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Built polymorphic agent: ${EXECUTABLE_NAME}"
    COMMAND ${CMAKE_COMMAND} -E echo "Architecture: ${ARCH_BITS}-bit"
    COMMAND ${CMAKE_COMMAND} -E echo "Build seed: ${RANDOM_SEED}"
)

# Install target
install(TARGETS ${EXECUTABLE_NAME}
    RUNTIME DESTINATION bin
)
