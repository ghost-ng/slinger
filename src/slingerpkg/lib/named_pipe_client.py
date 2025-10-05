"""
Named Pipe Client Implementation for Agent Communication
Supports both pywin32 and ctypes for cross-platform compatibility
"""

import struct
import time
from abc import ABC, abstractmethod


class NamedPipeClientBase(ABC):
    """Base class for named pipe clients"""

    def __init__(self, pipe_path, timeout):
        self.pipe_path = pipe_path
        self.timeout = timeout
        self.connected = False

    @abstractmethod
    def connect(self):
        """Connect to the named pipe"""
        pass

    @abstractmethod
    def disconnect(self):
        """Disconnect from the named pipe"""
        pass

    @abstractmethod
    def send_raw(self, data):
        """Send raw bytes to the pipe"""
        pass

    @abstractmethod
    def receive_raw(self, size):
        """Receive raw bytes from the pipe"""
        pass

    def send_message(self, message_type, data):
        """Send a structured message to the agent"""
        try:
            # Message format: [length:4][type:4][data:N]
            data_bytes = data.encode("utf-8") if isinstance(data, str) else data
            length = len(data_bytes)

            header = struct.pack("<II", length, message_type)
            full_message = header + data_bytes

            return self.send_raw(full_message)

        except Exception as e:
            print(f"Failed to send message: {e}")
            return False

    def receive_message(self):
        """Receive a structured message from the agent"""
        try:
            # Read header (8 bytes: length + type)
            header_data = self.receive_raw(8)
            if not header_data or len(header_data) != 8:
                return None, None

            length, msg_type = struct.unpack("<II", header_data)

            # Read message data
            if length > 0:
                data = self.receive_raw(length)
                if not data or len(data) != length:
                    return None, None
                return msg_type, data.decode("utf-8", errors="ignore")
            else:
                return msg_type, ""

        except Exception as e:
            print(f"Failed to receive message: {e}")
            return None, None

    def send_handshake(self):
        """Send handshake to agent"""
        return self.send_message(0x1003, "SLINGER_READY")  # HANDSHAKE type

    def send_command(self, command):
        """Send command to agent"""
        return self.send_message(0x1001, command)  # COMMAND type

    def receive_response(self):
        """Receive response from agent"""
        msg_type, data = self.receive_message()
        if msg_type == 0x1002:  # RESPONSE type
            return data
        return None


class NamedPipeClientWin32(NamedPipeClientBase):
    """Named pipe client using pywin32"""

    def __init__(self, pipe_path, timeout):
        super().__init__(pipe_path, timeout)
        self.handle = None

    def connect(self):
        """Connect using pywin32"""
        try:
            import win32pipe
            import win32file
            import pywintypes

            # Wait for pipe to be available
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    win32pipe.WaitNamedPipe(self.pipe_path, int(self.timeout * 1000))
                    break
                except pywintypes.error:
                    time.sleep(0.1)
                    continue
            else:
                return False

            # Open the pipe
            self.handle = win32file.CreateFile(
                self.pipe_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )

            if self.handle == win32file.INVALID_HANDLE_VALUE:
                return False

            self.connected = True
            return True

        except Exception as e:
            print(f"Win32 pipe connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect using pywin32"""
        try:
            if self.handle:
                import win32file

                win32file.CloseHandle(self.handle)
                self.handle = None
            self.connected = False
        except:
            pass

    def send_raw(self, data):
        """Send raw data using pywin32"""
        try:
            if not self.connected or not self.handle:
                return False

            import win32file

            bytes_written = 0
            total_bytes = len(data)

            while bytes_written < total_bytes:
                result, written = win32file.WriteFile(self.handle, data[bytes_written:])
                if result != 0:
                    return False
                bytes_written += written

            return True

        except Exception as e:
            print(f"Win32 send failed: {e}")
            return False

    def receive_raw(self, size):
        """Receive raw data using pywin32"""
        try:
            if not self.connected or not self.handle:
                return None

            import win32file

            result, data = win32file.ReadFile(self.handle, size)
            if result == 0:
                return data
            return None

        except Exception as e:
            print(f"Win32 receive failed: {e}")
            return None


class NamedPipeClientCtypes(NamedPipeClientBase):
    """Named pipe client using ctypes (cross-platform)"""

    def __init__(self, pipe_path, timeout):
        super().__init__(pipe_path, timeout)
        self.handle = None
        self._setup_ctypes()

    def _setup_ctypes(self):
        """Setup ctypes for Windows API calls"""
        try:
            import ctypes
            from ctypes import wintypes

            self.kernel32 = ctypes.windll.kernel32

            # Define Windows constants
            self.GENERIC_READ = 0x80000000
            self.GENERIC_WRITE = 0x40000000
            self.OPEN_EXISTING = 3
            self.INVALID_HANDLE_VALUE = -1

            # Setup function prototypes
            self.kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            self.kernel32.CreateFileW.restype = wintypes.HANDLE

            self.kernel32.WriteFile.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p,
            ]
            self.kernel32.WriteFile.restype = wintypes.BOOL

            self.kernel32.ReadFile.argtypes = [
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.c_void_p,
            ]
            self.kernel32.ReadFile.restype = wintypes.BOOL

        except Exception as e:
            print(f"Failed to setup ctypes: {e}")
            raise

    def connect(self):
        """Connect using ctypes"""
        try:
            import ctypes

            # Try to open the pipe
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                self.handle = self.kernel32.CreateFileW(
                    self.pipe_path,
                    self.GENERIC_READ | self.GENERIC_WRITE,
                    0,
                    None,
                    self.OPEN_EXISTING,
                    0,
                    None,
                )

                if self.handle != self.INVALID_HANDLE_VALUE:
                    self.connected = True
                    return True

                time.sleep(0.1)

            return False

        except Exception as e:
            print(f"Ctypes pipe connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect using ctypes"""
        try:
            if self.handle and self.handle != self.INVALID_HANDLE_VALUE:
                self.kernel32.CloseHandle(self.handle)
                self.handle = None
            self.connected = False
        except:
            pass

    def send_raw(self, data):
        """Send raw data using ctypes"""
        try:
            if not self.connected or not self.handle:
                return False

            import ctypes
            from ctypes import wintypes

            bytes_written = wintypes.DWORD(0)
            result = self.kernel32.WriteFile(
                self.handle, ctypes.c_char_p(data), len(data), ctypes.byref(bytes_written), None
            )

            return result and bytes_written.value == len(data)

        except Exception as e:
            print(f"Ctypes send failed: {e}")
            return False

    def receive_raw(self, size):
        """Receive raw data using ctypes"""
        try:
            if not self.connected or not self.handle:
                return None

            import ctypes
            from ctypes import wintypes

            buffer = ctypes.create_string_buffer(size)
            bytes_read = wintypes.DWORD(0)

            result = self.kernel32.ReadFile(
                self.handle, buffer, size, ctypes.byref(bytes_read), None
            )

            if result:
                return buffer.raw[: bytes_read.value]
            return None

        except Exception as e:
            print(f"Ctypes receive failed: {e}")
            return None
