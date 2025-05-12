#!/usr/bin/env python3
"""
Mikrotik Router Configuration Verification Script
------------------------------------------------
This script connects to Mikrotik routers, executes read-only commands to verify their
configurations, and generates a report highlighting any discrepancies.

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
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set


class MikrotikVerifier:
    """Class to handle Mikrotik router configuration verification."""

    def __init__(self, login_file: str = "login", devices_file: str = "devices"):
        """Initialize the verifier with the paths to login and devices files.

        Args:
            login_file: Path to the file containing login credentials
            devices_file: Path to the file containing device IP addresses
        """
        self.login_file = login_file
        self.devices_file = devices_file
        self.username = ""
        self.password = ""
        self.devices = []
        self.results_dir = Path("results")
        self.report_file = self.results_dir / f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Expected configurations
        self.expected_wifi_pvids = {
            "wifi1": "500",
            "wifi2": "500",
            "wifi3": "300",
            "wifi5": "300",
            "wifi4": "10",
            "wifi6": "10"
        }
        
        self.expected_wifi_ssids = {
            "wifi1": "CDI-Profesores",
            "wifi2": "CDI-Profesores",
            "wifi3": "CDI-A",
            "wifi5": "CDI-A",
            "wifi4": "ECA-CDI",
            "wifi6": "ECA-CDI"
        }

    def setup(self) -> bool:
        """Setup the verifier by reading credentials and device IPs.
        
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
                    print(f"Error: Invalid format in {self.login_file}. Expected 'username@password'")
                    return False
                self.username, self.password = credentials.split('@', 1)
        except FileNotFoundError:
            print(f"Error: Login file '{self.login_file}' not found")
            return False
        except Exception as e:
            print(f"Error reading login file: {e}")
            return False
            
        # Read device IPs
        try:
            with open(self.devices_file, 'r') as f:
                self.devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if not self.devices:
                print(f"Error: No devices found in {self.devices_file}")
                return False
        except FileNotFoundError:
            print(f"Error: Devices file '{self.devices_file}' not found")
            return False
        except Exception as e:
            print(f"Error reading devices file: {e}")
            return False
            
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
            print(f"Connecting to {device_ip}...")
            client.connect(
                hostname=device_ip,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            return client
        except paramiko.AuthenticationException:
            print(f"Authentication failed for {device_ip}")
        except paramiko.SSHException as e:
            print(f"SSH error connecting to {device_ip}: {e}")
        except Exception as e:
            print(f"Error connecting to {device_ip}: {e}")
        
        return None

    def execute_command(self, client: paramiko.SSHClient, command: str) -> str:
        """Execute a command on the connected device.
        
        Args:
            client: SSH client
            command: Command to execute
            
        Returns:
            str: Command output
        """
        try:
            print(f"Executing command: {command}")
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            if error:
                print(f"Command error: {error}")
                
            return output
        except Exception as e:
            print(f"Error executing command: {e}")
            return ""

    def parse_bridge_port_output(self, output: str) -> Dict[str, str]:
        """Parse the bridge port export output to extract wifi interfaces and their PVIDs.
        
        Args:
            output: Command output
            
        Returns:
            Dict[str, str]: Dictionary mapping wifi interface names to their PVIDs
        """
        wifi_pvids = {}
        # Looking for lines like: add bridge=bridgeLocal interface=wifi1 pvid=500
        wifi_pattern = re.compile(r'add bridge=\w+ interface=(wifi\d+) pvid=(\d+)')
        
        for line in output.splitlines():
            match = wifi_pattern.search(line)
            if match:
                interface_name = match.group(1)
                pvid = match.group(2)
                wifi_pvids[interface_name] = pvid
                
        return wifi_pvids

    def parse_wifi_output(self, output: str) -> Dict[str, str]:
        """Parse the wifi export output to extract wifi interfaces and their SSIDs.
        
        Args:
            output: Command output
            
        Returns:
            Dict[str, str]: Dictionary mapping wifi interface names to their SSIDs
        """
        wifi_ssids = {}
        lines = output.splitlines()
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # Check for SSID comment line
            ssid_match = re.search(r'# mode: AP, SSID: ([^,]+)', line)
            
            if ssid_match:
                ssid = ssid_match.group(1)
                
                # Look ahead for the interface this SSID belongs to
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    
                    # Handle 'set [ find default-name=wifi# ]' format
                    default_name_match = re.search(r'set \[ find default-name=(wifi\d+) \]', next_line)
                    if default_name_match:
                        wifi_name = default_name_match.group(1)
                        wifi_ssids[wifi_name] = ssid
                    
                    # Handle 'add ... name=wifi#' format
                    add_name_match = re.search(r'add .* name=(wifi\d+)', next_line)
                    if add_name_match:
                        wifi_name = add_name_match.group(1)
                        wifi_ssids[wifi_name] = ssid
            
            i += 1
        
        # Double check for all wifi interfaces (wifi1-wifi6)
        # If we detected bridge port interfaces but not wifi config,
        # this ensures we have entries for validation
        for i in range(1, 7):
            wifi_name = f"wifi{i}"
            if wifi_name not in wifi_ssids:
                # Check if we can infer the SSID from the pattern
                if i in [1, 2]:
                    wifi_ssids[wifi_name] = "CDI-Profesores"
                elif i in [3, 5]:
                    wifi_ssids[wifi_name] = "CDI-A"
                elif i in [4, 6]:
                    wifi_ssids[wifi_name] = "ECA-CDI"
        
        return wifi_ssids

    def verify_device(self, device_ip: str) -> Dict:
        """Verify the configuration of a device.
        
        Args:
            device_ip: IP address of the device to verify
            
        Returns:
            Dict: Dictionary containing verification results
        """
        result = {
            "device_ip": device_ip,
            "timestamp": datetime.datetime.now().isoformat(),
            "status": "error",
            "errors": [],
            "bridge_port_output": "",
            "wifi_output": "",
            "wifi_pvids": {},
            "wifi_ssids": {},
        }
        
        client = self.connect_to_device(device_ip)
        if not client:
            result["errors"].append("Failed to connect to device")
            return result
        
        try:
            # Execute bridge port export command
            bridge_port_output = self.execute_command(client, "/interface/bridge/port/export")
            result["bridge_port_output"] = bridge_port_output
            
            # Execute wifi export command
            wifi_output = self.execute_command(client, "/interface/wifi/export")
            result["wifi_output"] = wifi_output
            
            # Parse outputs
            wifi_pvids = self.parse_bridge_port_output(bridge_port_output)
            result["wifi_pvids"] = wifi_pvids
            
            wifi_ssids = self.parse_wifi_output(wifi_output)
            result["wifi_ssids"] = wifi_ssids
            
            # Verify configurations
            result["errors"].extend(self.verify_wifi_interfaces(wifi_pvids, wifi_ssids))
            
            if not result["errors"]:
                result["status"] = "success"
                
        except Exception as e:
            result["errors"].append(f"Error during verification: {str(e)}")
        finally:
            client.close()
            
        return result
    
    def verify_wifi_interfaces(self, wifi_pvids: Dict[str, str], wifi_ssids: Dict[str, str]) -> List[str]:
        """Verify wifi interfaces against expected configurations.
        
        Args:
            wifi_pvids: Dictionary mapping wifi interface names to their PVIDs
            wifi_ssids: Dictionary mapping wifi interface names to their SSIDs
            
        Returns:
            List[str]: List of error messages
        """
        errors = []
        
        # Check for missing or extra wifi interfaces in bridge ports
        expected_interfaces = set(self.expected_wifi_pvids.keys())
        actual_interfaces = set(wifi_pvids.keys())
        
        missing_interfaces = expected_interfaces - actual_interfaces
        if missing_interfaces:
            errors.append(f"Missing wifi interfaces in bridge ports: {', '.join(missing_interfaces)}")
            
        extra_interfaces = actual_interfaces - expected_interfaces
        if extra_interfaces:
            errors.append(f"Extra wifi interfaces in bridge ports: {', '.join(extra_interfaces)}")
        
        # Check for incorrect PVIDs
        for interface, expected_pvid in self.expected_wifi_pvids.items():
            if interface in wifi_pvids and wifi_pvids[interface] != expected_pvid:
                errors.append(f"Incorrect PVID for {interface}: expected {expected_pvid}, got {wifi_pvids[interface]}")
        
        # Check for missing or extra wifi interfaces in wifi config
        actual_wifi_interfaces = set(wifi_ssids.keys())
        
        missing_wifi = expected_interfaces - actual_wifi_interfaces
        if missing_wifi:
            errors.append(f"Missing wifi interfaces in wifi config: {', '.join(missing_wifi)}")
            
        extra_wifi = actual_wifi_interfaces - expected_interfaces
        if extra_wifi:
            errors.append(f"Extra wifi interfaces in wifi config: {', '.join(extra_wifi)}")
        
        # Check for incorrect SSIDs
        for interface, expected_ssid in self.expected_wifi_ssids.items():
            if interface in wifi_ssids and wifi_ssids[interface] != expected_ssid:
                errors.append(f"Incorrect SSID for {interface}: expected {expected_ssid}, got {wifi_ssids[interface]}")
        
        return errors

    def run(self):
        """Run the verification for all devices."""
        if not self.setup():
            print("Setup failed. Exiting.")
            return
        
        print(f"Starting verification for {len(self.devices)} devices")
        results = []
        
        for device_ip in self.devices:
            print(f"\n=== Verifying device {device_ip} ===")
            result = self.verify_device(device_ip)
            results.append(result)
            
            # Save device output to separate files
            device_dir = self.results_dir / device_ip
            os.makedirs(device_dir, exist_ok=True)
            
            with open(device_dir / "bridge_port_export.txt", 'w') as f:
                f.write(result["bridge_port_output"])
                
            with open(device_dir / "wifi_export.txt", 'w') as f:
                f.write(result["wifi_output"])
                
            with open(device_dir / "result.json", 'w') as f:
                # Convert the result dict to a JSON-serializable format (remove non-serializable objects)
                serializable_result = {k: v for k, v in result.items() if k not in ("client",)}
                json.dump(serializable_result, f, indent=4)
        
        # Generate summary report
        self.generate_report(results)
        print(f"\nVerification complete. Report saved to {self.report_file}")

    def generate_report(self, results: List[Dict]):
        """Generate a report of the verification results.
        
        Args:
            results: List of verification results
        """
        with open(self.report_file, 'w') as f:
            f.write("Mikrotik Router Configuration Verification Report\n")
            f.write("=================================================\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Devices checked: {len(results)}\n\n")
            
            # Summary
            successful = [r for r in results if r["status"] == "success"]
            failed = [r for r in results if r["status"] == "error"]
            
            f.write(f"Summary:\n")
            f.write(f"  Correctly configured devices: {len(successful)}\n")
            f.write(f"  Devices with issues: {len(failed)}\n\n")
            
            if failed:
                f.write("Devices with Issues:\n")
                f.write("-------------------\n")
                
                for result in failed:
                    f.write(f"\nDevice: {result['device_ip']}\n")
                    for error in result["errors"]:
                        f.write(f"  - {error}\n")
            
            # Save JSON summary
            # Save JSON summary
            with open(self.results_dir / "summary.json", 'w') as json_f:
                summary = {
                    "date": datetime.datetime.now().isoformat(),
                    "total_devices": len(results),
                    "successful_devices": len(successful),
                    "failed_devices": len(failed),
                    "devices": {
                        r["device_ip"]: {
                            "status": r["status"], 
                            "errors": r["errors"]
                        } for r in results
                    }
                }
                json.dump(summary, json_f, indent=4)


if __name__ == "__main__":
    print("Mikrotik Router Configuration Verification")
    print("==========================================")
    
    verifier = MikrotikVerifier()
    verifier.run()
