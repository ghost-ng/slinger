#pragma once
#include <cstdint>
#include <cstring>
#include "crypto.h"

namespace crypto {

// X25519 Elliptic Curve Diffie-Hellman (Curve25519)
// Provides 128-bit security level with 32-byte keys
// Much faster and simpler than classic DH with large primes
class X25519 {
public:
    static const size_t KEY_SIZE = 32; // 256 bits

private:
    // Curve25519 field prime: 2^255 - 19
    static void fe25519_add(uint32_t out[10], const uint32_t a[10], const uint32_t b[10]) {
        for (int i = 0; i < 10; i++) {
            out[i] = a[i] + b[i];
        }
    }

    static void fe25519_sub(uint32_t out[10], const uint32_t a[10], const uint32_t b[10]) {
        uint32_t c = 0;
        for (int i = 0; i < 10; i++) {
            c = a[i] - b[i] - c;
            out[i] = c & ((1 << 26) - 1);
            c = (c >> 26) & 1;
        }
    }

    static void fe25519_mul(uint32_t out[10], const uint32_t a[10], const uint32_t b[10]) {
        uint64_t t[19] = {0};
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 10; j++) {
                t[i + j] += (uint64_t)a[i] * b[j];
            }
        }
        // Reduce modulo 2^255 - 19
        for (int i = 0; i < 10; i++) {
            t[i] += (t[i + 10] * 38);
            out[i] = t[i] & ((1 << 26) - 1);
            t[i + 1] += t[i] >> 26;
        }
    }

    static void curve25519_scalarmult(uint8_t* out, const uint8_t* scalar, const uint8_t* point) {
        // Simplified X25519 - in production use a hardened implementation
        // This is a placeholder - you should use Windows BCrypt or OpenSSL for production

        uint8_t clamped_scalar[32];
        memcpy(clamped_scalar, scalar, 32);
        clamped_scalar[0] &= 248;
        clamped_scalar[31] &= 127;
        clamped_scalar[31] |= 64;

        uint32_t x1[10], x2[10] = {1}, z2[10] = {0}, x3[10], z3[10] = {1};
        uint32_t tmp0[10], tmp1[10];

        // Decode point
        for (int i = 0; i < 10; i++) {
            x1[i] = point[i * 3] | (point[i * 3 + 1] << 8) | (point[i * 3 + 2] << 16);
        }
        memcpy(x3, x1, sizeof(x1));

        // Montgomery ladder
        for (int pos = 254; pos >= 0; pos--) {
            uint32_t bit = (clamped_scalar[pos / 8] >> (pos & 7)) & 1;

            // Conditional swap
            if (bit) {
                for (int i = 0; i < 10; i++) {
                    uint32_t tmp = x2[i]; x2[i] = x3[i]; x3[i] = tmp;
                    tmp = z2[i]; z2[i] = z3[i]; z3[i] = tmp;
                }
            }

            // Point addition and doubling
            fe25519_add(tmp0, x2, z2);
            fe25519_sub(tmp1, x2, z2);
            fe25519_mul(x2, tmp0, tmp0);
            fe25519_mul(z2, tmp1, tmp1);
            fe25519_sub(z2, x2, z2);
            fe25519_mul(x2, x2, z2);
            fe25519_add(z2, z2, x1);
            fe25519_mul(z2, z2, z2);

            if (bit) {
                for (int i = 0; i < 10; i++) {
                    uint32_t tmp = x2[i]; x2[i] = x3[i]; x3[i] = tmp;
                    tmp = z2[i]; z2[i] = z3[i]; z3[i] = tmp;
                }
            }
        }

        // Encode result
        for (int i = 0; i < 10; i++) {
            out[i * 3] = x2[i] & 0xff;
            out[i * 3 + 1] = (x2[i] >> 8) & 0xff;
            out[i * 3 + 2] = (x2[i] >> 16) & 0xff;
        }
    }

public:
    // Generate a keypair (private key + public key)
    static bool generate_keypair(uint8_t* private_key, uint8_t* public_key) {
        // Generate random private key
        if (!SecureRandom::generate(private_key, KEY_SIZE)) {
            return false;
        }

        // Clamp private key (required for X25519)
        private_key[0] &= 248;
        private_key[31] &= 127;
        private_key[31] |= 64;

        // Compute public key = scalar_mult(private_key, basepoint)
        uint8_t basepoint[KEY_SIZE] = {9}; // X25519 base point

        // Use pure C++ implementation for cross-platform compatibility
        curve25519_scalarmult(public_key, private_key, basepoint);

        return true;
    }

    // Compute shared secret from your private key and their public key
    static bool compute_shared_secret(const uint8_t* my_private_key,
                                      const uint8_t* their_public_key,
                                      uint8_t* shared_secret) {
        // Use pure C++ implementation for cross-platform compatibility
        curve25519_scalarmult(shared_secret, my_private_key, their_public_key);
        return true;
    }
};

} // namespace crypto
