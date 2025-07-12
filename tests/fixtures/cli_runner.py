"""
CLI Test Runner for Slinger - Handles interaction with embedded CLI
"""
import subprocess
import threading
import queue
import time
import re
import os
import sys
from typing import Optional, List, Tuple, Dict, Any
from pathlib import Path
import pexpect


class SlingerTestRunner:
    """
    Runs Slinger in test mode with programmatic interaction.
    Uses pexpect for reliable CLI interaction.
    """
    
    def __init__(self, mock_server=None, test_mode=True):
        self.mock_server = mock_server
        self.process = None
        self.test_mode = test_mode
        self.command_history = []
        self.output_history = []
        self.prompt_pattern = r'slinger.*>'  # Match Slinger prompt
        
        # Test configuration
        self.timeout = 10
        self.encoding = 'utf-8'
        
        # Build command with test flags
        self.base_cmd = [
            sys.executable,
            '-m', 'slingerpkg.slinger',
            '--no-color',  # Disable color for easier parsing
        ]
        
        if test_mode:
            # Add test mode flag when implemented
            self.base_cmd.append('--test-mode')
    
    def start(self, host: str = "192.168.1.100", username: str = "testuser", 
              password: str = "testpass", domain: str = "", 
              auth_type: str = "password", **kwargs) -> bool:
        """Start Slinger with test configuration"""
        
        # Build command line
        cmd = self.base_cmd.copy()
        cmd.extend(['-host', host])
        cmd.extend(['-user', username])
        
        if auth_type == "password":
            cmd.extend(['-password', password])
        elif auth_type == "ntlm":
            cmd.extend(['-hashes', f":{kwargs.get('nthash', '')}"])
        elif auth_type == "kerberos":
            cmd.append('-k')
        
        if domain:
            cmd.extend(['-domain', domain])
        
        # Add any additional arguments
        for key, value in kwargs.items():
            if key not in ['nthash']:
                cmd.extend([f'-{key}', str(value)])
        
        try:
            # Use pexpect for better CLI interaction
            self.process = pexpect.spawn(
                cmd[0], 
                cmd[1:],
                encoding=self.encoding,
                timeout=self.timeout,
                env={**os.environ, 'TERM': 'dumb', 'NO_COLOR': '1'}
            )
            
            # Wait for initial prompt or error
            index = self.process.expect([
                self.prompt_pattern,
                'Authentication failed',
                'Connection failed',
                pexpect.EOF,
                pexpect.TIMEOUT
            ])
            
            if index == 0:
                # Successfully connected
                return True
            else:
                # Connection failed
                self.stop()
                return False
                
        except Exception as e:
            print(f"Failed to start Slinger: {e}")
            return False
    
    def send_command(self, command: str) -> str:
        """Send a command and return the output"""
        if not self.process or not self.process.isalive():
            raise RuntimeError("Slinger is not running")
        
        # Record command
        self.command_history.append(command)
        
        try:
            # Send command
            self.process.sendline(command)
            
            # Wait for prompt and capture output
            self.process.expect(self.prompt_pattern)
            
            # Get output (everything before the prompt)
            output = self.process.before.strip()
            
            # Remove the echoed command from output
            lines = output.split('\n')
            if lines and lines[0].strip() == command:
                output = '\n'.join(lines[1:])
            
            # Record output
            self.output_history.append((command, output))
            
            return output
            
        except pexpect.TIMEOUT:
            raise TimeoutError(f"Command timed out: {command}")
        except pexpect.EOF:
            raise RuntimeError("Slinger process terminated unexpectedly")
    
    def send_command_no_wait(self, command: str) -> None:
        """Send a command without waiting for response (for commands like exit)"""
        if not self.process or not self.process.isalive():
            return
        
        self.process.sendline(command)
    
    def expect_output(self, pattern: str, timeout: Optional[int] = None) -> bool:
        """Wait for expected output pattern"""
        if not self.process or not self.process.isalive():
            return False
        
        try:
            self.process.expect(pattern, timeout=timeout or self.timeout)
            return True
        except (pexpect.TIMEOUT, pexpect.EOF):
            return False
    
    def get_last_output(self) -> str:
        """Get the last command output"""
        if self.output_history:
            return self.output_history[-1][1]
        return ""
    
    def is_alive(self) -> bool:
        """Check if Slinger is still running"""
        return self.process is not None and self.process.isalive()
    
    def stop(self) -> None:
        """Stop Slinger process"""
        if self.process and self.process.isalive():
            try:
                # Try graceful exit first
                self.send_command_no_wait('exit')
                self.process.expect(pexpect.EOF, timeout=2)
            except:
                # Force terminate if graceful exit fails
                self.process.terminate(force=True)
            
            self.process = None
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure cleanup on exit"""
        self.stop()


class BatchCommandRunner:
    """Run multiple commands in sequence and collect results"""
    
    def __init__(self, runner: SlingerTestRunner):
        self.runner = runner
        self.results = []
    
    def run_commands(self, commands: List[str]) -> List[Tuple[str, str, bool]]:
        """
        Run a list of commands and return results.
        Returns list of (command, output, success) tuples.
        """
        self.results = []
        
        for cmd in commands:
            try:
                output = self.runner.send_command(cmd)
                success = not any(err in output.lower() for err in ['error', 'failed', 'denied'])
                self.results.append((cmd, output, success))
            except Exception as e:
                self.results.append((cmd, str(e), False))
        
        return self.results
    
    def get_failed_commands(self) -> List[Tuple[str, str]]:
        """Get list of failed commands and their errors"""
        return [(cmd, output) for cmd, output, success in self.results if not success]
    
    def all_successful(self) -> bool:
        """Check if all commands were successful"""
        return all(success for _, _, success in self.results)


class InteractiveTester:
    """
    Helper for testing interactive features like tab completion
    """
    
    def __init__(self, runner: SlingerTestRunner):
        self.runner = runner
    
    def test_tab_completion(self, partial_command: str) -> List[str]:
        """Test tab completion for a partial command"""
        if not self.runner.process:
            raise RuntimeError("Runner not started")
        
        # Send partial command without newline
        self.runner.process.send(partial_command)
        
        # Send tab character
        self.runner.process.send('\t')
        
        # Wait a bit for completion
        time.sleep(0.1)
        
        # Read any completion output
        try:
            self.runner.process.expect('.*', timeout=0.5)
            output = self.runner.process.before
            
            # Parse completions from output
            # This will depend on how Slinger formats completions
            completions = self._parse_completions(output)
            
            # Clear the line
            self.runner.process.send('\x03')  # Ctrl+C to cancel
            
            return completions
        except:
            return []
    
    def _parse_completions(self, output: str) -> List[str]:
        """Parse tab completion output"""
        # Implementation depends on Slinger's completion format
        lines = output.strip().split('\n')
        completions = []
        
        for line in lines:
            # Extract completion options
            if line.strip():
                completions.append(line.strip())
        
        return completions


class MockConnectionPatcher:
    """
    Patches Slinger to use mock connections for testing
    """
    
    def __init__(self, mock_server):
        self.mock_server = mock_server
        self.patches = []
    
    def __enter__(self):
        """Patch SMB and DCE connections"""
        from unittest.mock import patch
        
        # Patch SMBConnection
        smb_patch = patch('impacket.smbconnection.SMBConnection')
        mock_smb_class = smb_patch.start()
        mock_smb_class.return_value = self.mock_server.get_connection()
        self.patches.append(smb_patch)
        
        # Patch DCE/RPC connections
        dce_patch = patch('impacket.dcerpc.v5.transport.DCERPCTransportFactory')
        mock_dce_factory = dce_patch.start()
        mock_transport = mock_dce_factory.return_value.get_dce_rpc.return_value
        mock_transport.connect.return_value = True
        mock_transport.bind.return_value = True
        self.patches.append(dce_patch)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop all patches"""
        for patch in self.patches:
            patch.stop()


# Convenience functions for common test scenarios

def create_test_runner(mock_server=None, **kwargs) -> SlingerTestRunner:
    """Create a test runner with common defaults"""
    runner = SlingerTestRunner(mock_server=mock_server, test_mode=True)
    
    # Default connection parameters
    defaults = {
        'host': '192.168.1.100',
        'username': 'testuser',
        'password': 'testpass'
    }
    defaults.update(kwargs)
    
    if runner.start(**defaults):
        return runner
    else:
        raise RuntimeError("Failed to start test runner")


def run_command_test(command: str, mock_server=None, **kwargs) -> Tuple[bool, str]:
    """
    Quick function to test a single command.
    Returns (success, output) tuple.
    """
    with create_test_runner(mock_server, **kwargs) as runner:
        try:
            output = runner.send_command(command)
            success = 'error' not in output.lower()
            return success, output
        except Exception as e:
            return False, str(e)


def run_scenario_test(commands: List[str], mock_server=None, **kwargs) -> Dict[str, Any]:
    """
    Run a complete test scenario with multiple commands.
    Returns detailed results.
    """
    with create_test_runner(mock_server, **kwargs) as runner:
        batch = BatchCommandRunner(runner)
        results = batch.run_commands(commands)
        
        return {
            'all_successful': batch.all_successful(),
            'results': results,
            'failed_commands': batch.get_failed_commands(),
            'command_count': len(commands),
            'success_count': sum(1 for _, _, success in results if success)
        }