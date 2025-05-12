#!/usr/bin/env python3
"""
Mikrotik Router Command Execution Script
----------------------------------------
This script connects to Mikrotik routers, executes commands on them, and generates
a report of the execution results. It will stop execution if any error is detected,
except for connection errors.

Requirements:
- Python 3.6+
- paramiko library (install with: pip install paramiko)
"""

import os
import sys
import re
import json
import datetime
import paramiko
import time
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set


class MikrotikUpdater:
    """Class to handle Mikrotik router command execution."""

    def __init__(self, login_file: str = "../login", devices_file: str = "devices", commands_file: str = "commands"):
        """Initialize the updater with the paths to login and devices files.

        Args:
            login_file: Path to the file containing login credentials
            devices_file: Path to the file containing device IP addresses
            commands_file: Path to the file containing commands to execute
        """
        self.login_file = login_file
        self.devices_file = devices_file
        self.commands_file = commands_file
        self.username = ""
        self.password = ""
        self.devices = []
        self.commands = []
        self.results_dir = Path("results")
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.report_file = self.results_dir / f"report_{timestamp}.txt"
        self.log_file = self.results_dir / f"execution_log_{timestamp}.txt"
        self.outputs_dir = self.results_dir / f"output_{timestamp}"
        self.outputs_summary_file = self.results_dir / f"outputs_summary_{timestamp}.txt"
        
        # Error keywords to check in command output
        self.error_keywords = ["error", "warning", "fail", "invalid", "failure"]
        
        # Setup logging
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.outputs_dir, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def log_event(self, event_type: str, message: str, device_ip: str = None, command: str = None, output: str = None, error: bool = False):
        """Log an event with relevant metadata."""
        log_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': event_type,
            'message': message
        }
        if device_ip:
            log_data['device_ip'] = device_ip
        if command:
            log_data['command'] = command
        if output:
            log_data['output'] = output

        log_message = json.dumps(log_data)
        if error:
            logging.error(log_message)
        else:
            logging.info(log_message)

    def setup(self) -> bool:
        """Setup the updater by reading credentials, device IPs, and commands.
        
        Returns:
            bool: True if setup was successful, False otherwise
        """
        # Create results directory if it doesn't exist
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Read login credentials
        try:
            with open(self.login_file, 'r') as f:
                credentials = f.readline().strip()
                if '@' not in credentials:
                    error_msg = f"Invalid format in {self.login_file}. Expected 'username@password'"
                    self.log_event('SETUP', error_msg, error=True)
                    print(f"Error: {error_msg}")  # Keep this print for user feedback
                    return False
                self.username, self.password = credentials.split('@', 1)
        except FileNotFoundError:
            error_msg = f"Login file '{self.login_file}' not found"
            self.log_event('SETUP', error_msg, error=True)
            print(f"Error: {error_msg}")  # Keep this print for user feedback
            return False
        except Exception as e:
            error_msg = f"Error reading login file: {e}"
            self.log_event('SETUP', error_msg, error=True)
            print(f"Error: {error_msg}")  # Keep this print for user feedback
            return False
            
        # Read device IPs
        try:
            with open(self.devices_file, 'r') as f:
                self.devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not self.devices:
                error_msg = f"No devices found in {self.devices_file}"
                self.log_event('SETUP', error_msg, error=True)
                print(f"Error: {error_msg}")  # Keep this print for user feedback
                return False
        except FileNotFoundError:
            error_msg = f"Devices file '{self.devices_file}' not found"
            self.log_event('SETUP', error_msg, error=True)
            print(f"Error: {error_msg}")  # Keep this print for user feedback
            return False
        except Exception as e:
            error_msg = f"Error reading devices file: {e}"
            self.log_event('SETUP', error_msg, error=True)
            print(f"Error: {error_msg}")  # Keep this print for user feedback
            return False
        
        # Read commands
        try:
            with open(self.commands_file, 'r') as f:
                self.commands = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not self.commands:
                error_msg = f"No commands found in {self.commands_file}"
                self.log_event('SETUP', error_msg, error=True)
                print(f"Error: {error_msg}")  # Keep this print for user feedback
                return False
        except FileNotFoundError:
            error_msg = f"Commands file '{self.commands_file}' not found"
            self.log_event('SETUP', error_msg, error=True)
            print(f"Error: {error_msg}")  # Keep this print for user feedback
            return False
        except Exception as e:
            error_msg = f"Error reading commands file: {e}"
            self.log_event('SETUP', error_msg, error=True)
            print(f"Error: {error_msg}")  # Keep this print for user feedback
            return False
            
        self.log_event('SETUP', "Setup completed successfully")
        return True

    def connect_to_device(self, device_ip: str) -> Optional[paramiko.SSHClient]:
        """Connect to a device via SSH.
        
        Args:
            device_ip: IP address of the device to connect to
            
        Returns:
            Optional[paramiko.SSHClient]: SSH client if connection was successful, None otherwise
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.log_event('CONNECTION', f"Attempting connection to {device_ip}", device_ip=device_ip)
            print(f"Connecting to {device_ip}...")  # Keep this print for user feedback
            client.connect(
                hostname=device_ip,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            self.log_event('CONNECTION', f"Successfully connected to {device_ip}", device_ip=device_ip)
            return client
        except paramiko.AuthenticationException:
            error_msg = f"Authentication failed for {device_ip}"
            print(error_msg)
            self.log_event('CONNECTION', error_msg, device_ip=device_ip, error=True)
        except paramiko.SSHException as e:
            error_msg = f"SSH error connecting to {device_ip}: {e}"
            print(error_msg)
            self.log_event('CONNECTION', error_msg, device_ip=device_ip, error=True)
        except Exception as e:
            error_msg = f"Error connecting to {device_ip}: {e}"
            print(error_msg)
            self.log_event('CONNECTION', error_msg, device_ip=device_ip, error=True)
        
        return None

    def execute_command(self, client: paramiko.SSHClient, command: str, device_ip: str = None) -> Tuple[str, bool]:
        """Execute a command on the connected device.
        
        Args:
            client: SSH client
            command: Command to execute
            device_ip: IP address of the device (optional)
            
        Returns:
            Tuple[str, bool]: Command output and error status
                The error status is True if an error was detected in the output
        """
        try:
            # Get device IP if not provided
            if device_ip is None:
                try:
                    transport = client.get_transport()
                    device_ip = transport.getpeername()[0] if transport else "unknown"
                except:
                    device_ip = "unknown"
                    
            self.log_event('COMMAND', f"Executing command: {command}", device_ip=device_ip, command=command)
            print(f"Executing command: {command}")  # Keep this print for user feedback
            
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error:
                self.log_event('COMMAND', f"Command error: {error}", device_ip=device_ip, command=command, output=error, error=True)
                print(f"Command error: {error}")  # Keep this print for user feedback
                return error, True
            
            # Check for error keywords in the output
            for keyword in self.error_keywords:
                if keyword.lower() in output.lower():
                    error_msg = f"Error keyword '{keyword}' found in output"
                    self.log_event('COMMAND', error_msg, device_ip=device_ip, command=command, output=output, error=True)
                    print(error_msg)  # Keep this print for user feedback
                    return output, True
            
            self.log_event('COMMAND', "Command executed successfully", device_ip=device_ip, command=command, output=output)
            return output, False
        except Exception as e:
            error_msg = f"Error executing command: {e}"
            self.log_event('COMMAND', error_msg, device_ip=device_ip, command=command, error=True)
            print(error_msg)  # Keep this print for user feedback
            return str(e), True

    def process_device(self, device_ip: str, processed_count: int) -> Dict:
        """Process a device by executing commands on it.
        
        Args:
            device_ip: IP address of the device to process
            processed_count: Number of devices successfully processed so far
            
        Returns:
            Dict: Dictionary containing processing results
        """
        self.log_event('DEVICE', f"Starting device processing", device_ip=device_ip)
        
        result = {
            "device_ip": device_ip,
            "timestamp": datetime.datetime.now().isoformat(),
            "status": "error",
            "errors": [],
            "command_outputs": {},
            "connection_error": False
        }
        
        client = self.connect_to_device(device_ip)
        if not client:
            error_msg = "Failed to connect to device"
            result["errors"].append(error_msg)
            result["connection_error"] = True
            self.log_event('DEVICE', error_msg, device_ip=device_ip, error=True)
            return result
        
        try:
            # Execute each command
            for command in self.commands:
                output, has_error = self.execute_command(client, command, device_ip)
                result["command_outputs"][command] = output
                
                # Save raw command output to a separate file in the outputs directory
                # Create a descriptive filename from the command
                safe_command = re.sub(r'[^\w\-_\.]', '_', command)
                safe_command = safe_command.strip('_')  # Remove leading/trailing underscores
                
                # Create a clean, readable filename with device IP and command
                output_filename = f"{device_ip}_{safe_command}.txt"
                
                # Write ONLY the raw output to file
                with open(self.outputs_dir / output_filename, 'w') as f:
                    f.write(output)
                
                if has_error:
                    error_msg = f"Error detected in output of command: {command}"
                    result["errors"].append(error_msg)
                    self.log_event('DEVICE', error_msg, device_ip=device_ip, command=command, error=True)
                    # Don't set connection_error flag here as this is a command error
                    break  # Stop processing more commands for this device
            
            # If no errors, mark as success
            if not result["errors"]:
                result["status"] = "success"
                self.log_event('DEVICE', "Device processing completed successfully", device_ip=device_ip)
                
        except Exception as e:
            error_msg = f"Error during command execution: {str(e)}"
            result["errors"].append(error_msg)
            self.log_event('DEVICE', error_msg, device_ip=device_ip, error=True)
        finally:
            self.log_event('CONNECTION', "Closing connection", device_ip=device_ip)
            client.close()
            
        return result

    def run(self):
        """Run the command execution for all devices."""
        if not self.setup():
            self.log_event('RUN', "Setup failed. Exiting.", error=True)
            print("Setup failed. Exiting.")  # Keep this print for user feedback
            return
        
        self.log_event('RUN', f"Starting command execution for {len(self.devices)} devices")
        print(f"Starting command execution for {len(self.devices)} devices")  # Keep this print for user feedback
        results = []
        successful_count = 0
        
        for i, device_ip in enumerate(self.devices):
            self.log_event('RUN', f"Processing device {device_ip} ({i+1}/{len(self.devices)})", device_ip=device_ip)
            print(f"\n=== Processing device {device_ip} ({i+1}/{len(self.devices)}) ===")  # Keep this print for user feedback
            result = self.process_device(device_ip, successful_count)
            results.append(result)
            
            # Save result JSON in the device directory
            device_dir = self.results_dir / device_ip
            os.makedirs(device_dir, exist_ok=True)
            
            # Save result JSON
            with open(device_dir / "result.json", 'w') as f:
                # Convert the result dict to a JSON-serializable format
                serializable_result = {k: v for k, v in result.items() if k not in ("client",)}
                json.dump(serializable_result, f, indent=4)
            
            # Check if we need to stop due to errors (ignoring connection errors)
            if result["status"] == "error" and not result["connection_error"]:
                error_msg = f"ERROR DETECTED ON DEVICE {device_ip}: {'; '.join(result['errors'])}"
                self.log_event('RUN', error_msg, device_ip=device_ip, error=True)
                self.log_event('RUN', f"Stopping execution after processing {i+1} devices ({successful_count} successful)", error=True)
                print(f"\n!!! {error_msg} !!!")  # Keep this print for user feedback
                print(f"Stopping execution after processing {i+1} devices ({successful_count} successful)")  # Keep this print for user feedback
                break
            
            # Count successful devices
            if result["status"] == "success":
                successful_count += 1
        
        # Generate outputs summary
        self.log_event('REPORT', "Generating outputs summary")
        self.generate_outputs_summary(results)
        
        # Generate summary report
        self.log_event('REPORT', "Generating execution report")
        self.generate_report(results, successful_count)
        
        # Log completion
        self.log_event('RUN', f"Execution complete. Report saved to {self.report_file}")
        self.log_event('RUN', f"Command execution log saved to {self.log_file}")
        self.log_event('RUN', f"Raw command outputs saved to {self.outputs_dir}")
        self.log_event('RUN', f"Outputs summary saved to {self.outputs_summary_file}")
        
        # User feedback
        print(f"\nExecution complete. Report saved to {self.report_file}")
        print(f"Command execution log saved to {self.log_file}")
        print(f"Raw command outputs saved to {self.outputs_dir}")
        print(f"Outputs summary saved to {self.outputs_summary_file}")
        print(f"Note: All command outputs are saved as separate files in {self.outputs_dir}")

    def generate_outputs_summary(self, results: List[Dict]):
        """Generate a summary file with all command outputs organized by device."""
        with open(self.outputs_summary_file, 'w') as f:
            f.write("MIKROTIK COMMAND OUTPUTS SUMMARY\n")
            f.write("==============================\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total devices: {len(results)}\n\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                device_ip = result['device_ip']
                f.write(f"DEVICE: {device_ip}\n")
                f.write("=" * (len(device_ip) + 8) + "\n\n")
                
                if result['connection_error']:
                    f.write("CONNECTION ERROR: Could not connect to device\n\n")
                    f.write("=" * 80 + "\n\n")
                    continue
                    
                if result['errors']:
                    f.write("ERRORS:\n")
                    for error in result['errors']:
                        f.write(f"- {error}\n")
                    f.write("\n")
                    
                f.write("OUTPUTS:\n")
                for command, output in result['command_outputs'].items():
                    f.write(f"\nCommand: {command}\n")
                    f.write("-" * (len(command) + 9) + "\n")
                    f.write(output)
                    if not output.endswith("\n"):
                        f.write("\n")
                f.write("\n" + "=" * 80 + "\n\n")

    def generate_report(self, results: List[Dict], successful_count: int):
        """Generate a report of the command execution results.
        
        Args:
            results: List of execution results
            successful_count: Number of devices successfully processed
        """
        with open(self.report_file, 'w') as f:
            f.write("Mikrotik Router Command Execution Report\n")
            f.write("=======================================\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Devices processed: {len(results)}/{len(self.devices)}\n\n")
            
            # Summary
            connection_errors = [r for r in results if r["connection_error"]]
            command_errors = [r for r in results if r["status"] == "error" and not r["connection_error"]]
            
            f.write(f"Summary:\n")
            f.write(f"  Successfully processed devices: {successful_count}\n")
            f.write(f"  Devices with connection errors: {len(connection_errors)}\n")
            f.write(f"  Devices with command errors: {len(command_errors)}\n\n")
            
            if connection_errors:
                f.write("Devices with Connection Errors:\n")
                f.write("------------------------------\n")
                for result in connection_errors:
                    f.write(f"  - {result['device_ip']}\n")
                f.write("\n")
            
            if command_errors:
                f.write("Devices with Command Errors:\n")
                f.write("---------------------------\n")
                for result in command_errors:
                    f.write(f"\nDevice: {result['device_ip']}\n")
                    for error in result["errors"]:
                        f.write(f"  - {error}\n")
            
            # Commands executed
            f.write("\nCommands Executed:\n")
            f.write("-----------------\n")
            for i, command in enumerate(self.commands):
                f.write(f"  {i+1}. {command}\n")
            
            # Save JSON summary
            with open(self.results_dir / "summary.json", 'w') as json_f:
                summary = {
                    "date": datetime.datetime.now().isoformat(),
                    "total_devices": len(self.devices),
                    "processed_devices": len(results),
                    "successful_devices": successful_count,
                    "connection_error_devices": len(connection_errors),
                    "command_error_devices": len(command_errors),
                    "devices": {
                        r["device_ip"]: {
                            "status": r["status"], 
                            "errors": r["errors"],
                            "connection_error": r["connection_error"]
                        } for r in results
                    }
                }
                json.dump(summary, json_f, indent=4)
        self.log_event('REPORT', "Report generation complete")


if __name__ == "__main__":
    # Print header for user feedback
    print("Mikrotik Router Command Execution Script")
    print("======================================")
    
    updater = MikrotikUpdater()
    updater.log_event('MAIN', "Starting Mikrotik Router Command Execution Script")
    updater.run()
    updater.log_event('MAIN', "Script execution completed")

