#pragma once
#include <windows.h>
#include <string>
#include <random>
#include <chrono>

namespace obfuscated {

// Compile-time random seed generation
constexpr uint32_t compile_seed() {
#ifdef BUILD_SEED
    return BUILD_SEED;
#else
    return 12345; // Default fallback
#endif
}

// Runtime random seed for additional entropy
inline uint32_t random_seed() {
    static uint32_t seed = static_cast<uint32_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()
    ) ^ compile_seed();
    seed = seed * 1103515245 + 12345;
    return seed;
}

// Derive encryption key from index and base seed
constexpr uint8_t derive_key(size_t index) {
    return static_cast<uint8_t>((compile_seed() * 0x9E3779B9 + index) & 0xFF);
}

// Compile-time string obfuscation
template<size_t N, uint32_t KEY = compile_seed()>
struct ObfuscatedString {
    char data[N];

    constexpr ObfuscatedString(const char (&str)[N]) : data{} {
        for (size_t i = 0; i < N - 1; ++i) {
            data[i] = str[i] ^ derive_key(i + KEY);
        }
        data[N - 1] = '\0';
    }

    std::string decrypt() const {
        std::string result;
        result.reserve(N - 1);
        for (size_t i = 0; i < N - 1; ++i) {
            result += static_cast<char>(data[i] ^ derive_key(i + KEY));
        }
        return result;
    }
};

// Function name obfuscation macro
#define OBF_FUNC_NAME(name) obf_##name##_##BUILD_SEED

// String obfuscation macro
#define OBF_STRING(str) (obfuscated::ObfuscatedString<sizeof(str)>(str))

// Control flow obfuscation helpers
template<typename T>
inline T obfuscate_value(T value) {
    volatile uint32_t noise = random_seed();
    return value ^ (noise & 0) ^ (noise & 0);
}

// Dead code insertion for obfuscation
inline void insert_junk_code() {
    volatile int junk = random_seed();
    junk *= 0x1337;
    junk += 0xDEADBEEF;
    junk ^= 0xCAFEBABE;
    (void)junk; // Suppress unused variable warning
}

// Anti-debug timing checks (lightweight)
inline bool check_timing() {
    auto start = std::chrono::high_resolution_clock::now();
    insert_junk_code();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    return duration.count() < 1000; // Basic timing check
}

// Simple XOR encoder for runtime strings
class XOREncoder {
private:
    uint8_t key;

public:
    XOREncoder() : key(static_cast<uint8_t>(random_seed() & 0xFF)) {}

    std::string encode(const std::string& input) {
        std::string result = input;
        for (char& c : result) {
            c ^= key;
        }
        return result;
    }

    std::string decode(const std::string& input) {
        return encode(input); // XOR is symmetric
    }
};

// Stack-based string obfuscation
template<size_t SIZE>
class StackString {
private:
    char buffer[SIZE];
    size_t length;

public:
    StackString() : length(0) {
        memset(buffer, 0, SIZE);
    }

    StackString(const char* str) : length(0) {
        assign(str);
    }

    void assign(const char* str) {
        length = strlen(str);
        if (length >= SIZE) length = SIZE - 1;

        uint8_t xor_key = static_cast<uint8_t>(random_seed() & 0xFF);
        for (size_t i = 0; i < length; ++i) {
            buffer[i] = str[i] ^ xor_key;
        }
        buffer[length] = '\0';

        // Decode in place
        for (size_t i = 0; i < length; ++i) {
            buffer[i] ^= xor_key;
        }
    }

    const char* c_str() const { return buffer; }
    size_t size() const { return length; }
};

} // namespace obfuscated

// Obfuscation macros for common use
#define OBFUSCATED_FUNC(ret, name, ...) \
    ret OBF_FUNC_NAME(name)(__VA_ARGS__)

#define OBFUSCATED_CALL(name, ...) \
    OBF_FUNC_NAME(name)(__VA_ARGS__)
