#pragma once
#include "crypto.h"
#include <cstring>
#include <string>
#include <sstream>
#include <functional>

namespace crypto {

/**
 * Simplified Challenge-Response Authentication Protocol
 *
 * Flow:
 * 1. Agent sends 16-byte random nonce on connection
 * 2. Client responds with HMAC-SHA256(passphrase, nonce) + encrypted command
 * 3. Agent verifies HMAC and derives session key from nonce+passphrase_hash
 * 4. All future messages encrypted with session-specific AES-256-GCM key
 *
 * Security Properties:
 * - Requires attacker to have: pcap + binary + active participation
 * - Replay attacks prevented by random nonce per session
 * - Forward secrecy through session-specific keys (each nonce creates unique key)
 * - No plaintext passphrase in agent (only SHA256 hash)
 *
 * Protocol Constants:
 * - NONCE_SIZE = 16 bytes
 * - HMAC_SIZE = 32 bytes (SHA-256 output)
 * - PBKDF2_ITERATIONS = 10000
 * - SESSION_KEY_SIZE = 32 bytes (AES-256)
 */
class AuthProtocol {
private:
    uint8_t passphrase_hash[32];      // SHA256(passphrase) - embedded in agent
    uint8_t session_key[32];          // PBKDF2(passphrase_hash, nonce)
    uint8_t session_nonce[16];        // Random nonce for this session
    bool authenticated;

public:
    static const size_t NONCE_SIZE = 16;
    static const size_t HMAC_SIZE = 32;
    static const size_t SESSION_KEY_SIZE = 32;
    static const int PBKDF2_ITERATIONS = 10000;

    AuthProtocol() : authenticated(false) {
        SecureMemory::zero(passphrase_hash, sizeof(passphrase_hash));
        SecureMemory::zero(session_key, sizeof(session_key));
        SecureMemory::zero(session_nonce, sizeof(session_nonce));
    }

    ~AuthProtocol() {
        // Securely zero all sensitive data
        SecureMemory::zero(passphrase_hash, sizeof(passphrase_hash));
        SecureMemory::zero(session_key, sizeof(session_key));
        SecureMemory::zero(session_nonce, sizeof(session_nonce));
    }

    /**
     * Initialize with passphrase (called at agent build time)
     *
     * Stores SHA256(passphrase) in agent binary - NOT the plaintext passphrase.
     * This allows HMAC verification without exposing the passphrase.
     *
     * @param passphrase User's passphrase
     * @return true on success
     */
    bool initialize_with_passphrase(const char* passphrase) {
        // Hash the passphrase with SHA256
        // This is what gets embedded in the agent binary
        SHA256 sha256;
        sha256.update((const uint8_t*)passphrase, strlen(passphrase));
        sha256.finalize(passphrase_hash);

        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("AUTH_INIT", "Passphrase hash initialized");
        #endif

        return true;
    }

    /**
     * Agent-side: Send challenge and authenticate client
     *
     * Steps:
     * 1. Generate random 16-byte nonce
     * 2. Send nonce to client (unencrypted)
     * 3. Receive HMAC response from client
     * 4. Verify HMAC matches expected value
     * 5. Derive session key from nonce+passphrase_hash
     * 6. Mark as authenticated
     *
     * @param send_raw Send raw bytes (nonce)
     * @param read_raw Read raw bytes (HMAC response)
     * @return true if authentication successful
     */
    bool authenticate_as_agent(
        std::function<bool(const void*, size_t)> send_raw,
        std::function<bool(void*, size_t)> read_raw) {

        // Step 1: Generate random nonce for this session
        if (!SecureRandom::generate(session_nonce, NONCE_SIZE)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("AUTH", "Failed to generate session nonce");
            #endif
            return false;
        }

        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("AUTH", "Generated session nonce (16 bytes)");
        #endif

        // Step 2: Send nonce to client
        if (!send_raw(session_nonce, NONCE_SIZE)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("AUTH", "Failed to send nonce to client");
            #endif
            return false;
        }

        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("AUTH", "Sent nonce to client, waiting for HMAC response...");
        #endif

        // Step 3: Receive HMAC response (32 bytes)
        uint8_t received_hmac[HMAC_SIZE];
        if (!read_raw(received_hmac, HMAC_SIZE)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("AUTH", "Failed to receive HMAC response from client");
            #endif
            return false;
        }

        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("AUTH", "Received HMAC response (32 bytes)");
            // Log received HMAC in hex
            std::string received_hex;
            for (int i = 0; i < HMAC_SIZE; i++) {
                char buf[3];
                sprintf(buf, "%02x", received_hmac[i]);
                received_hex += buf;
            }
            DEBUG_LOG_CAT("AUTH", "Received HMAC: " + received_hex);
        #endif

        // Step 4: Compute expected HMAC = HMAC-SHA256(passphrase_hash, nonce)
        uint8_t expected_hmac[HMAC_SIZE];

        #ifdef DEBUG_MODE
            // Log input parameters BEFORE calling HMAC
            DEBUG_LOG_CAT("AUTH", "About to compute HMAC with:");
            DEBUG_LOG_CAT("AUTH", "  sizeof(passphrase_hash) = " + std::to_string(sizeof(passphrase_hash)));
            DEBUG_LOG_CAT("AUTH", "  NONCE_SIZE = " + std::to_string(NONCE_SIZE));

            // Log passphrase hash
            std::string hash_hex;
            for (int i = 0; i < 32; i++) {
                char buf[3];
                sprintf(buf, "%02x", passphrase_hash[i]);
                hash_hex += buf;
            }
            DEBUG_LOG_CAT("AUTH", "  Passphrase hash: " + hash_hex);

            // Log session nonce
            std::string nonce_hex;
            for (int i = 0; i < NONCE_SIZE; i++) {
                char buf[3];
                sprintf(buf, "%02x", session_nonce[i]);
                nonce_hex += buf;
            }
            DEBUG_LOG_CAT("AUTH", "  Session nonce: " + nonce_hex);
        #endif

        if (!HMAC_SHA256::compute(passphrase_hash, sizeof(passphrase_hash),
                                  session_nonce, NONCE_SIZE,
                                  expected_hmac)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("AUTH", "Failed to compute expected HMAC");
            #endif
            return false;
        }

        #ifdef DEBUG_MODE
            // Log computed HMAC result
            std::string expected_hex;
            for (int i = 0; i < HMAC_SIZE; i++) {
                char buf[3];
                sprintf(buf, "%02x", expected_hmac[i]);
                expected_hex += buf;
            }
            DEBUG_LOG_CAT("AUTH", "Computed expected HMAC: " + expected_hex);
        #endif

        // Step 5: Verify HMAC (constant-time comparison)
        if (!HMAC_SHA256::constant_time_compare(received_hmac, expected_hmac, HMAC_SIZE)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("AUTH", "HMAC verification FAILED - wrong passphrase");
            #endif
            return false; // Wrong passphrase - disconnect
        }

        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("AUTH", "HMAC verification SUCCESS");
        #endif

        // Step 6: Derive session key using PBKDF2
        // session_key = PBKDF2-HMAC-SHA256(passphrase_hash, nonce, 10k iterations)
        if (!PBKDF2::derive_key((const char*)passphrase_hash, sizeof(passphrase_hash),
                               session_nonce, NONCE_SIZE,
                               PBKDF2_ITERATIONS,
                               session_key, SESSION_KEY_SIZE)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("AUTH", "Failed to derive session key");
            #endif
            return false;
        }

        #ifdef DEBUG_MODE
            DEBUG_LOG_CAT("AUTH", "Session key derived - authentication complete");
        #endif

        authenticated = true;
        return true;
    }

    /**
     * Derive session key from passphrase and nonce
     *
     * Used by both agent and client to derive the same session key.
     * Agent uses passphrase_hash, client uses actual passphrase.
     *
     * @param passphrase_or_hash Passphrase (client) or passphrase hash (agent)
     * @param passphrase_len Length of passphrase/hash
     * @param nonce Session nonce
     * @param nonce_len Length of nonce (should be 16)
     * @param output Output buffer for session key (32 bytes)
     * @return true on success
     */
    bool derive_session_key(const uint8_t* passphrase_or_hash, size_t passphrase_len,
                           const uint8_t* nonce, size_t nonce_len,
                           uint8_t* output) {
        return PBKDF2::derive_key((const char*)passphrase_or_hash, passphrase_len,
                                 nonce, nonce_len,
                                 PBKDF2_ITERATIONS,
                                 output, SESSION_KEY_SIZE);
    }

    /**
     * Encrypt a message with AES-256-GCM using session key
     *
     * Message format: ENCRYPTED|iv_hex|tag_hex|ciphertext_hex
     *
     * @param plaintext Message to encrypt
     * @param output Formatted encrypted message
     * @return true on success
     */
    bool encrypt_message(const std::string& plaintext, std::string& output) {
        if (!authenticated) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("ENCRYPT", "Cannot encrypt - not authenticated");
            #endif
            return false;
        }

        AES_GCM::EncryptedData encrypted;
        if (!AES_GCM::encrypt(session_key,
                             (const uint8_t*)plaintext.c_str(),
                             plaintext.length(),
                             encrypted)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("ENCRYPT", "AES-GCM encryption failed");
            #endif
            return false;
        }

        // Format: ENCRYPTED|iv_hex|tag_hex|ciphertext_hex
        std::ostringstream oss;
        oss << "ENCRYPTED|";

        // IV (12 bytes)
        for (size_t i = 0; i < encrypted.iv.size(); i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", encrypted.iv[i]);
            oss << buf;
        }
        oss << "|";

        // Tag (16 bytes)
        for (size_t i = 0; i < encrypted.tag.size(); i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", encrypted.tag[i]);
            oss << buf;
        }
        oss << "|";

        // Ciphertext
        for (size_t i = 0; i < encrypted.ciphertext.size(); i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", encrypted.ciphertext[i]);
            oss << buf;
        }

        output = oss.str();
        return true;
    }

    /**
     * Decrypt a message with AES-256-GCM using session key
     *
     * Expected format: ENCRYPTED|iv_hex|tag_hex|ciphertext_hex
     *
     * @param input Formatted encrypted message
     * @param plaintext Decrypted message output
     * @return true on success
     */
    bool decrypt_message(const std::string& input, std::string& plaintext) {
        if (!authenticated) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("DECRYPT", "Cannot decrypt - not authenticated");
            #endif
            return false;
        }

        if (input.substr(0, 10) != "ENCRYPTED|") {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("DECRYPT", "Invalid message format - missing ENCRYPTED| prefix");
            #endif
            return false;
        }

        // Parse: ENCRYPTED|iv_hex|tag_hex|ciphertext_hex
        size_t pos1 = input.find('|', 10);
        size_t pos2 = input.find('|', pos1 + 1);

        if (pos1 == std::string::npos || pos2 == std::string::npos) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("DECRYPT", "Invalid message format - missing separators");
            #endif
            return false;
        }

        std::string iv_hex = input.substr(10, pos1 - 10);
        std::string tag_hex = input.substr(pos1 + 1, pos2 - pos1 - 1);
        std::string ciphertext_hex = input.substr(pos2 + 1);

        AES_GCM::EncryptedData encrypted;

        // Parse IV (should be 12 bytes = 24 hex chars)
        encrypted.iv.resize(iv_hex.length() / 2);
        for (size_t i = 0; i < encrypted.iv.size(); i++) {
            sscanf(iv_hex.substr(i * 2, 2).c_str(), "%2hhx", &encrypted.iv[i]);
        }

        // Parse tag (should be 16 bytes = 32 hex chars)
        encrypted.tag.resize(tag_hex.length() / 2);
        for (size_t i = 0; i < encrypted.tag.size(); i++) {
            sscanf(tag_hex.substr(i * 2, 2).c_str(), "%2hhx", &encrypted.tag[i]);
        }

        // Parse ciphertext
        encrypted.ciphertext.resize(ciphertext_hex.length() / 2);
        for (size_t i = 0; i < encrypted.ciphertext.size(); i++) {
            sscanf(ciphertext_hex.substr(i * 2, 2).c_str(), "%2hhx", &encrypted.ciphertext[i]);
        }

        // Decrypt
        std::vector<uint8_t> decrypted(encrypted.ciphertext.size());
        size_t decrypted_len = 0;

        if (!AES_GCM::decrypt(session_key, encrypted,
                             decrypted.data(), decrypted_len)) {
            #ifdef DEBUG_MODE
                DEBUG_LOG_CAT("DECRYPT", "AES-GCM decryption failed");
            #endif
            return false;
        }

        plaintext.assign((char*)decrypted.data(), decrypted_len);
        return true;
    }

    bool is_authenticated() const { return authenticated; }

    void reset() {
        SecureMemory::zero(session_key, sizeof(session_key));
        SecureMemory::zero(session_nonce, sizeof(session_nonce));
        authenticated = false;
    }
};

} // namespace crypto
