#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #pragma comment(lib, "advapi32.lib")
#else
    #include <openssl/evp.h>
    #include <openssl/rand.h>
    #include <openssl/sha.h>
    #include <openssl/hmac.h>
#endif

namespace crypto {

// AES-256-GCM encryption wrapper
class AES_GCM {
private:
    static const size_t KEY_SIZE = 32;      // 256 bits
    static const size_t IV_SIZE = 12;       // 96 bits (recommended for GCM)
    static const size_t TAG_SIZE = 16;      // 128 bits

public:
    struct EncryptedData {
        std::vector<uint8_t> iv;
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;
    };

#ifdef _WIN32
    static bool encrypt(const uint8_t* key, const uint8_t* plaintext, size_t plaintext_len,
                       EncryptedData& output) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        NTSTATUS status;

        // Open algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) return false;

        // Set chaining mode to GCM
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                  (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                  sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        // Generate key object
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                           (PUCHAR)key, KEY_SIZE, 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        // Generate random IV
        output.iv.resize(IV_SIZE);
        BCryptGenRandom(NULL, output.iv.data(), IV_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        // Setup auth info
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = output.iv.data();
        authInfo.cbNonce = IV_SIZE;
        output.tag.resize(TAG_SIZE);
        authInfo.pbTag = output.tag.data();
        authInfo.cbTag = TAG_SIZE;

        // Encrypt
        ULONG ciphertext_len = 0;
        output.ciphertext.resize(plaintext_len);
        status = BCryptEncrypt(hKey, (PUCHAR)plaintext, plaintext_len, &authInfo,
                              NULL, 0, output.ciphertext.data(), plaintext_len,
                              &ciphertext_len, 0);

        // Cleanup
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        return BCRYPT_SUCCESS(status);
    }

    static bool decrypt(const uint8_t* key, const EncryptedData& input,
                       uint8_t* plaintext, size_t& plaintext_len) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        NTSTATUS status;

        // Open algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) return false;

        // Set chaining mode to GCM
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                  (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                  sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        // Generate key object
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                           (PUCHAR)key, KEY_SIZE, 0);
        if (!BCRYPT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        // Setup auth info
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = const_cast<uint8_t*>(input.iv.data());
        authInfo.cbNonce = IV_SIZE;
        authInfo.pbTag = const_cast<uint8_t*>(input.tag.data());
        authInfo.cbTag = TAG_SIZE;

        // Decrypt
        ULONG decrypted_len = 0;
        status = BCryptDecrypt(hKey, (PUCHAR)input.ciphertext.data(),
                              input.ciphertext.size(), &authInfo,
                              NULL, 0, plaintext, input.ciphertext.size(),
                              &decrypted_len, 0);

        plaintext_len = decrypted_len;

        // Cleanup
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        return BCRYPT_SUCCESS(status);
    }
#else
    // Linux OpenSSL implementation
    static bool encrypt(const uint8_t* key, const uint8_t* plaintext, size_t plaintext_len,
                       EncryptedData& output) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        // Generate random IV
        output.iv.resize(IV_SIZE);
        RAND_bytes(output.iv.data(), IV_SIZE);

        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, output.iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Encrypt
        output.ciphertext.resize(plaintext_len);
        int len = 0;
        if (EVP_EncryptUpdate(ctx, output.ciphertext.data(), &len, plaintext, plaintext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Finalize
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, output.ciphertext.data() + len, &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Get tag
        output.tag.resize(TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, output.tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    static bool decrypt(const uint8_t* key, const EncryptedData& input,
                       uint8_t* plaintext, size_t& plaintext_len) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, input.iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Decrypt
        int len = 0;
        if (EVP_DecryptUpdate(ctx, plaintext, &len, input.ciphertext.data(),
                             input.ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                               const_cast<uint8_t*>(input.tag.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        // Finalize (verifies tag)
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false; // Tag verification failed
        }

        plaintext_len = len + final_len;
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
#endif
};

// SHA-256 hash wrapper
class SHA256 {
private:
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    bool initialized;
#else
    EVP_MD_CTX* ctx;
#endif

public:
    static const size_t HASH_SIZE = 32; // 256 bits

    SHA256() {
#ifdef _WIN32
        initialized = false;
        hAlg = NULL;
        hHash = NULL;

        // Open algorithm provider
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) return;

        // Create hash object
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        if (BCRYPT_SUCCESS(status)) {
            initialized = true;
        } else {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            hAlg = NULL;
        }
#else
        ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
#endif
    }

    ~SHA256() {
#ifdef _WIN32
        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
#else
        if (ctx) EVP_MD_CTX_free(ctx);
#endif
    }

    void update(const uint8_t* data, size_t len) {
#ifdef _WIN32
        if (initialized) {
            BCryptHashData(hHash, const_cast<uint8_t*>(data), len, 0);
        }
#else
        EVP_DigestUpdate(ctx, data, len);
#endif
    }

    bool finalize(uint8_t* output) {
#ifdef _WIN32
        if (!initialized) return false;
        NTSTATUS status = BCryptFinishHash(hHash, output, HASH_SIZE, 0);
        return BCRYPT_SUCCESS(status);
#else
        unsigned int len = HASH_SIZE;
        return EVP_DigestFinal_ex(ctx, output, &len) == 1;
#endif
    }

    // Static one-shot hash function
    static bool hash(const uint8_t* data, size_t data_len, uint8_t* output) {
        SHA256 hasher;
        hasher.update(data, data_len);
        return hasher.finalize(output);
    }
};

// HMAC-SHA256 wrapper
class HMAC_SHA256 {
public:
    static const size_t HASH_SIZE = 32; // 256 bits

#ifdef _WIN32
    static bool compute(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t data_len,
                       uint8_t* output) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status;

        #ifdef DEBUG_MODE
            std::string key_hex, data_hex;
            for (size_t i = 0; i < key_len && i < 32; i++) {
                char buf[3];
                sprintf(buf, "%02x", key[i]);
                key_hex += buf;
            }
            for (size_t i = 0; i < data_len && i < 32; i++) {
                char buf[3];
                sprintf(buf, "%02x", data[i]);
                data_hex += buf;
            }
            DEBUG_LOG_CAT("HMAC_COMPUTE", "key_len=" + std::to_string(key_len) +
                         " data_len=" + std::to_string(data_len));
            DEBUG_LOG_CAT("HMAC_COMPUTE", "key=" + key_hex);
            DEBUG_LOG_CAT("HMAC_COMPUTE", "data=" + data_hex);
        #endif

        // Open algorithm
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                            NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!BCRYPT_SUCCESS(status)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("HMAC_COMPUTE", "BCryptOpenAlgorithmProvider failed: " + std::to_string(status));
            #endif
            return false;
        }

        // Create hash object with HMAC key
        // NOTE: Must cast size_t to ULONG for BCrypt API
        ULONG key_len_ulong = static_cast<ULONG>(key_len);
        status = BCryptCreateHash(hAlg, &hHash, NULL, 0,
                                 const_cast<uint8_t*>(key), key_len_ulong, 0);
        if (!BCRYPT_SUCCESS(status)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("HMAC_COMPUTE", "BCryptCreateHash failed: " + std::to_string(status));
            #endif
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        // Hash data
        ULONG data_len_ulong = static_cast<ULONG>(data_len);
        status = BCryptHashData(hHash, const_cast<uint8_t*>(data), data_len_ulong, 0);
        if (!BCRYPT_SUCCESS(status)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("HMAC_COMPUTE", "BCryptHashData failed: " + std::to_string(status));
            #endif
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        // Get result
        status = BCryptFinishHash(hHash, output, HASH_SIZE, 0);
        if (!BCRYPT_SUCCESS(status)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("HMAC_COMPUTE", "BCryptFinishHash failed: " + std::to_string(status));
            #endif
        } else {
            #ifdef DEBUG_MODE
                std::string output_hex;
                for (size_t i = 0; i < HASH_SIZE; i++) {
                    char buf[3];
                    sprintf(buf, "%02x", output[i]);
                    output_hex += buf;
                }
                DEBUG_LOG_CAT("HMAC_COMPUTE", "result=" + output_hex);
            #endif
        }

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        return BCRYPT_SUCCESS(status);
    }
#else
    static bool compute(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t data_len,
                       uint8_t* output) {
        unsigned int len = HASH_SIZE;
        return HMAC(EVP_sha256(), key, key_len, data, data_len, output, &len) != NULL;
    }
#endif

    // Constant-time comparison to prevent timing attacks
    static bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
        uint8_t result = 0;
        for (size_t i = 0; i < len; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
};

// PBKDF2-HMAC-SHA256 for key derivation
class PBKDF2 {
public:
    static const size_t DEFAULT_ITERATIONS = 100000;

#ifdef _WIN32
    static bool derive_key(const char* passphrase, size_t pass_len,
                          const uint8_t* salt, size_t salt_len,
                          uint32_t iterations, uint8_t* output, size_t output_len) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        NTSTATUS status;

        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                            NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (!BCRYPT_SUCCESS(status)) return false;

        status = BCryptDeriveKeyPBKDF2(hAlg,
                                      (PUCHAR)passphrase, pass_len,
                                      const_cast<PUCHAR>(salt), salt_len,
                                      iterations, output, output_len, 0);

        BCryptCloseAlgorithmProvider(hAlg, 0);
        return BCRYPT_SUCCESS(status);
    }
#else
    static bool derive_key(const char* passphrase, size_t pass_len,
                          const uint8_t* salt, size_t salt_len,
                          uint32_t iterations, uint8_t* output, size_t output_len) {
        return PKCS5_PBKDF2_HMAC(passphrase, pass_len, salt, salt_len,
                                iterations, EVP_sha256(), output_len, output) == 1;
    }
#endif
};

// Secure random number generation
class SecureRandom {
public:
#ifdef _WIN32
    static bool generate(uint8_t* buffer, size_t length) {
        return BCryptGenRandom(NULL, buffer, length,
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }
#else
    static bool generate(uint8_t* buffer, size_t length) {
        return RAND_bytes(buffer, length) == 1;
    }
#endif
};

// Secure memory operations
class SecureMemory {
public:
    static void zero(void* ptr, size_t length) {
#ifdef _WIN32
        SecureZeroMemory(ptr, length);
#else
        explicit_bzero(ptr, length);
#endif
    }
};

} // namespace crypto
