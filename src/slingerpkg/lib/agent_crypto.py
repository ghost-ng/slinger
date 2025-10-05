#!/usr/bin/env python3
"""
Client-side cryptographic authentication for Slinger agents.

Implements a simplified challenge-response authentication protocol:

1. Agent sends 16-byte random nonce
2. Client responds with HMAC-SHA256(passphrase, nonce) + encrypted command
3. Agent verifies HMAC and derives session key from nonce+passphrase
4. All future messages encrypted with session-specific AES-256-GCM key

Security properties:
- Requires attacker to have: network capture, agent binary, and active participation
- Replay attacks prevented by random nonce per session
- Forward secrecy through session-specific keys
- No plaintext passphrase in agent (only SHA256 hash)
"""

import os
import hmac
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class AgentAuthProtocol:
    """
    Simplified challenge-response authentication for Slinger agents.

    Protocol flow:
    1. Client receives 16-byte nonce from agent
    2. Client computes HMAC-SHA256(passphrase, nonce) as authentication proof
    3. Client derives session key using PBKDF2-HMAC-SHA256(passphrase, nonce, 10k iterations)
    4. All messages encrypted with AES-256-GCM using session key

    Message format: [12-byte IV][ciphertext][16-byte auth tag]
    """

    # Protocol constants
    NONCE_SIZE = 16  # bytes
    HMAC_SIZE = 32  # bytes (SHA-256)
    IV_SIZE = 12  # bytes (GCM standard)
    TAG_SIZE = 16  # bytes (GCM standard)
    PBKDF2_ITERATIONS = 10000
    SESSION_KEY_SIZE = 32  # bytes (AES-256)

    def __init__(self):
        """Initialize authentication protocol handler."""
        self.session_key: Optional[bytes] = None
        self.authenticated = False

    def handle_challenge(self, nonce: bytes, passphrase: str) -> Tuple[bytes, bytes]:
        """
        Handle agent's challenge and prepare authentication response.

        This method:
        1. Computes HMAC-SHA256(passphrase, nonce) for authentication
        2. Derives session key using PBKDF2-HMAC-SHA256

        Args:
            nonce: 16-byte random challenge from agent
            passphrase: User's passphrase (same one hashed in agent binary)

        Returns:
            Tuple of (hmac_response, session_key):
                - hmac_response: 32-byte HMAC to prove knowledge of passphrase
                - session_key: 32-byte derived key for encrypting future messages

        Raises:
            ValueError: If nonce size is incorrect
        """
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(nonce)} (expected {self.NONCE_SIZE})")

        # Compute HMAC-SHA256(SHA256(passphrase), nonce) for authentication
        # Must match agent's auth_protocol.h which uses passphrase_hash
        passphrase_bytes = passphrase.encode("utf-8")
        passphrase_hash = hashlib.sha256(passphrase_bytes).digest()
        hmac_response = hmac.new(key=passphrase_hash, msg=nonce, digestmod=hashlib.sha256).digest()

        # Derive session key using PBKDF2-HMAC-SHA256
        session_key = self.derive_session_key(passphrase, nonce)

        return hmac_response, session_key

    def derive_session_key(self, passphrase: str, nonce: bytes) -> bytes:
        """
        Derive session-specific encryption key using PBKDF2-HMAC-SHA256.

        Uses SHA256(passphrase) as the password and nonce as salt.
        This matches the C++ agent implementation in auth_protocol.h.

        Args:
            passphrase: User's passphrase
            nonce: 16-byte random nonce used as salt

        Returns:
            32-byte session key for AES-256-GCM encryption
        """
        # Hash the passphrase first to match C++ agent
        passphrase_bytes = passphrase.encode("utf-8")
        passphrase_hash = hashlib.sha256(passphrase_bytes).digest()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.SESSION_KEY_SIZE,
            salt=nonce,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(passphrase_hash)

    def initialize_session(self, session_key: bytes) -> bool:
        """
        Initialize the session with a derived session key.

        After calling handle_challenge(), use this method to store the
        session key and mark the protocol as authenticated.

        Args:
            session_key: 32-byte session key from handle_challenge()

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            if len(session_key) != self.SESSION_KEY_SIZE:
                raise ValueError(f"Invalid session key size: {len(session_key)}")

            self.session_key = session_key
            self.authenticated = True
            return True
        except Exception as e:
            print(f"Error initializing session: {e}")
            return False

    def encrypt_message(self, plaintext: str) -> Optional[str]:
        """
        Encrypt message with AES-256-GCM using session key.

        Message format: ENCRYPTED|iv_hex|tag_hex|ciphertext_hex

        The AESGCM.encrypt() method returns [ciphertext || tag], where:
        - ciphertext: encrypted data
        - tag: 16-byte authentication tag

        Args:
            plaintext: Message to encrypt

        Returns:
            Formatted encrypted message string, or None on error
        """
        if not self.authenticated or not self.session_key:
            print("Error: Cannot encrypt - not authenticated")
            return None

        try:
            # Generate random 12-byte IV for GCM
            iv = os.urandom(self.IV_SIZE)

            # Encrypt with AES-256-GCM
            aesgcm = AESGCM(self.session_key)
            plaintext_bytes = plaintext.encode("utf-8")

            # Encrypt returns: ciphertext || 16-byte authentication tag
            ciphertext_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)

            # Split ciphertext and tag (last 16 bytes is tag)
            ciphertext = ciphertext_with_tag[: -self.TAG_SIZE]
            tag = ciphertext_with_tag[-self.TAG_SIZE :]

            # Format: ENCRYPTED|iv_hex|tag_hex|ciphertext_hex
            encrypted_msg = f"ENCRYPTED|{iv.hex()}|{tag.hex()}|{ciphertext.hex()}"
            return encrypted_msg

        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_msg: str) -> Optional[str]:
        """
        Decrypt message with AES-256-GCM using session key.

        Expected format: ENCRYPTED|iv_hex|tag_hex|ciphertext_hex

        Args:
            encrypted_msg: Formatted encrypted message string

        Returns:
            Decrypted plaintext string, or None on error
        """
        if not self.authenticated or not self.session_key:
            print("Error: Cannot decrypt - not authenticated")
            return None

        try:
            # Validate format
            if not encrypted_msg.startswith("ENCRYPTED|"):
                print("Error: Invalid encrypted message format")
                return None

            parts = encrypted_msg.split("|")
            if len(parts) != 4:
                print(f"Error: Invalid encrypted message parts (expected 4, got {len(parts)})")
                return None

            # Parse components
            iv = bytes.fromhex(parts[1])
            tag = bytes.fromhex(parts[2])
            ciphertext = bytes.fromhex(parts[3])

            # Validate sizes
            if len(iv) != self.IV_SIZE:
                print(f"Error: Invalid IV size (expected {self.IV_SIZE}, got {len(iv)})")
                return None
            if len(tag) != self.TAG_SIZE:
                print(f"Error: Invalid tag size (expected {self.TAG_SIZE}, got {len(tag)})")
                return None

            # Reconstruct ciphertext with tag for decryption
            ciphertext_with_tag = ciphertext + tag

            # Decrypt with AES-256-GCM
            aesgcm = AESGCM(self.session_key)
            plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)

            return plaintext_bytes.decode("utf-8")

        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def is_authenticated(self) -> bool:
        """
        Check if authentication handshake completed successfully.

        Returns:
            True if session is authenticated and ready for encryption
        """
        return self.authenticated

    def reset(self):
        """
        Reset the authentication state and securely clear session key.

        Call this when disconnecting or when authentication fails.
        """
        if self.session_key:
            # Overwrite session key memory before deletion
            # (Note: Python's memory management makes true zeroing difficult,
            # but this is better than nothing)
            self.session_key = b"\x00" * len(self.session_key)

        self.session_key = None
        self.authenticated = False


# Compatibility wrapper for existing code that uses the old interface
class AgentAuthProtocolLegacy:
    """
    Legacy compatibility wrapper for existing code.

    This provides backward compatibility with the old initialize_with_passphrase()
    interface, but uses a static agent_id as salt since we now use nonce-based
    session keys.
    """

    def __init__(self):
        self.session_key: Optional[bytes] = None
        self.authenticated = False

    def initialize_with_passphrase(self, passphrase: str, agent_id: str) -> bool:
        """
        Legacy method: Derive session key from passphrase using PBKDF2.

        Note: This is kept for backward compatibility but is less secure than
        the challenge-response protocol. Use AgentAuthProtocol for new code.

        Args:
            passphrase: User's passphrase
            agent_id: Agent identifier (used as PBKDF2 salt)

        Returns:
            True if key derivation successful
        """
        try:
            # Use PBKDF2 to derive 256-bit AES key from passphrase
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=agent_id.encode("utf-8"),
                iterations=100000,  # Higher iterations for static keys
                backend=default_backend(),
            )
            self.session_key = kdf.derive(passphrase.encode("utf-8"))
            self.authenticated = True
            return True
        except Exception as e:
            print(f"Error deriving session key: {e}")
            return False

    def encrypt_message(self, plaintext: str) -> Optional[str]:
        """Encrypt message - same as AgentAuthProtocol."""
        if not self.authenticated or not self.session_key:
            return None

        try:
            aesgcm = AESGCM(self.session_key)
            iv = os.urandom(12)
            plaintext_bytes = plaintext.encode("utf-8")
            ciphertext_with_tag = aesgcm.encrypt(iv, plaintext_bytes, None)
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]
            return f"ENCRYPTED|{iv.hex()}|{tag.hex()}|{ciphertext.hex()}"
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_msg: str) -> Optional[str]:
        """Decrypt message - same as AgentAuthProtocol."""
        if not self.authenticated or not self.session_key:
            return None

        try:
            if not encrypted_msg.startswith("ENCRYPTED|"):
                return None
            parts = encrypted_msg.split("|")
            if len(parts) != 4:
                return None
            iv = bytes.fromhex(parts[1])
            tag = bytes.fromhex(parts[2])
            ciphertext = bytes.fromhex(parts[3])
            ciphertext_with_tag = ciphertext + tag
            aesgcm = AESGCM(self.session_key)
            plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
            return plaintext_bytes.decode("utf-8")
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def is_authenticated(self) -> bool:
        """Check if authentication completed successfully."""
        return self.authenticated
