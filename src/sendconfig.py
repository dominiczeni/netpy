#!/usr/bin/env python3
from nornir import InitNornir
from nornir.plugins.inventory import SimpleInventory
from nornir.core.plugins.inventory import InventoryPluginRegister
from nornir_utils.plugins.tasks.files import write_file
from getpass import getpass
from datetime import datetime
from pathlib import Path
from nornir.core.filter import F
from nornir_netmiko.tasks import netmiko_send_command
from nornir_utils.plugins.functions import print_result
import argparse
import sys
import os
import createinventory
import upload_to_sharepoint
import subprocess
import paramiko
import time


def filter_inventory(nr, site=None, function=None):
    filter=None
    if site and function:
        filter = F(site=site) & F(function=function)
    elif site:
        filter = F(site=site)
    elif function:
        filter = F(function=function)
    if filter:
        return nr.filter(filter)
    return nr

def run_commands(task, base_dir="/app/files/"):
    commands_file = task.host.data.get('commands')
    host_id = task.host.get('name')
    if commands_file:
        full_path = os.path.join(base_dir, commands_file)
        if os.path.exists(full_path):
            with open(full_path, 'r') as file:
                commands = file.read().splitlines()
            
            # Store all results in a list
            all_results = []
            
            for command in commands:
                # Skip empty lines or comments
                if not command.strip() or command.strip().startswith('#'):
                    continue
                    
                platform = task.host.get('platform')
                if platform == "paloalto_panos":
                    cmd_result = task.run(
                        task=netmiko_send_command,
                        command_string=command.strip(),
                        name=f"run command {command} on {host_id}",
                        expect_string='>'
                    )
                else:
                    cmd_result = task.run(
                        task=netmiko_send_command,
                        command_string=command.strip(),
                        name=f"run command {command} on {host_id}",
                        read_timeout=180
                    )
                
                # Give a short delay between commands to ensure complete output collection
                time.sleep(0.5)
                
                # Store the result
                all_results.append(cmd_result)
                
            return all_results
        else:
            print(f"Warning: Command file {full_path} for host {host_id} does not exist.")
    else:
        print(f"Warning: No 'commands' attribute found for host {host_id}.")

def write_output(task, **kwargs):
    r = task.params.get("r")
    host_key = task.host.get("name")
    hostname = task.host.hostname
    
    # Ensure the output directory exists
    output_dir = "/app/files/output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create a unique timestamp for this run
    dt = datetime.now().strftime("%m%d%Y%-H%M%S")
    output_filename = f"{output_dir}/{host_key}-{dt}.txt"
    
    # Clear the file if it exists and add a header
    with open(output_filename, 'w') as file:
        file.write(f"# Output for {host_key} ({hostname}) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    # Create a list to hold all results before writing
    all_results = []
    
    # Process each command result
    count = 0
    while (count := count + 1) < len(r[host_key]):
        command_name = r[host_key][count].name
        command_result = r[host_key][count].result
        
        # Clean up the command name to get just the actual command
        clean_command = command_name
        if "run command " in command_name:
            clean_command = command_name.replace("run command ", "")
            if f" on {host_key}" in clean_command:
                clean_command = clean_command.replace(f" on {host_key}", "")
        
        # Format the output with clear section markers
        # Include both the hostname and the device name in the banner
        command_output = {
            "command": clean_command,
            "result": command_result
        }
        
        all_results.append(command_output)
    
    # Now write all results to the file with proper separation
    with open(output_filename, 'a') as file:
        for cmd in all_results:
            file.write(
                "\n\n"
                "########################################\n"
                f"## Start Command Output - {hostname} ({host_key})\n"
                f"## {cmd['command']}\n"
                "########################################\n\n"
                f"{cmd['result']}\n\n"
                "########################################\n"
                "## End Command Output\n"
                "########################################\n\n"
            )
    
    print(f"Output for {host_key} written to {output_filename}")
    return output_filename

def setup_jumpbox_connection(jumpbox_type, host, account):
    """
    Set up the jumpbox connection for a host using Paramiko directly.
    This avoids using proxy_jump_host parameter which appears to be problematic.
    """
    
    # Get connection parameters
    jumpbox_host = os.environ.get('JB1_HOST')
    jumpbox_username = os.environ.get('JB1_USER')
    jumpbox_password = os.environ.get('JB1_PASS')
    jumpbox_port = int(os.environ.get('JB1_PORT', 22))
    
    # Make sure we have the correct target username and password
    # For account variables like UN1, UN2, etc., ensure we're using the actual values
    target_username = host.username
    target_password = host.password
    
    if account and account.startswith('UN') and account in ['UN1', 'UN2', 'UN3', 'UN4']:
        env_var_name = f"PW{account[2:]}"  # Extract the number and create PW1, PW2, etc.
        if os.environ.get(account):
            target_username = os.environ.get(account)
            print(f"Target username resolved from {account}: '{target_username}'")
        if os.environ.get(env_var_name):
            target_password = os.environ.get(env_var_name)
            print(f"Target password resolved from {env_var_name}")
            
    # Verify we have a non-empty username
    if not target_username or target_username.strip() == '':
        print("ERROR: Target username is empty! Please check your environment variables.")
        target_username = input("Please enter the target username: ")
        
    print(f"Using target credentials - Username: '{target_username}'")
    
    # For linux/unix jumpboxes, we use a direct Paramiko channel
    if jumpbox_type in ['linux', 'unix']:
        # Create SSH client for jump box
        proxy = paramiko.SSHClient()
        proxy.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the jump box
        print(f"Connecting to {jumpbox_type} jump box at {jumpbox_host}...")
        proxy.connect(
            hostname=jumpbox_host,
            username=jumpbox_username,
            password=jumpbox_password,
            port=jumpbox_port
        )
        
        # Create a transport channel through the jump box
        transport = proxy.get_transport()
        dest_addr = (host.hostname, int(host.port or 22))
        src_addr = (jumpbox_host, jumpbox_port)
        
        # Create the channel
        channel = transport.open_channel("direct-tcpip", dest_addr, src_addr)
        
        # Store the proxy client to prevent it from being garbage collected
        host.connection_options['netmiko'].extras['_proxy_client'] = proxy
        host.connection_options['netmiko'].extras['sock'] = channel
        
        print(f"Successfully configured {host.name} to connect via {jumpbox_type} jump box")
        return True
        
    # For Cisco jumpboxes, we create a custom solution
    elif jumpbox_type in ['cisco_ios', 'cisco_xe', 'cisco_nxos']:
        jumpbox_secret = os.environ.get('JB1_SECRET', '')
        
        # Create a session log file for debugging
        log_file = f"/tmp/{host.name}_jumpbox_session.log"
        host.connection_options['netmiko'].extras['session_log'] = log_file
        
        print(f"For Cisco jump box connectivity, creating a special session handler...")
        
        # Create a special SSH client proxy class that will be used to manage the Cisco jumpbox connection
        class CiscoJumpBoxProxy:
            def __init__(self, jumpbox_params, target_params):
                self.jumpbox_params = jumpbox_params
                self.target_params = target_params
                self.jumpbox_conn = None
                self.connected = False
            
            def connect(self):
                import netmiko
                # First connect to the jumpbox
                self.jumpbox_conn = netmiko.ConnectHandler(
                    device_type=self.jumpbox_params['device_type'],
                    host=self.jumpbox_params['host'],
                    username=self.jumpbox_params['username'],
                    password=self.jumpbox_params['password'],
                    secret=self.jumpbox_params['secret'],
                    port=self.jumpbox_params['port'],
                    session_log=self.jumpbox_params['log_file']
                )
                
                # Enter enable mode if secret is provided
                if self.jumpbox_params['secret']:
                    self.jumpbox_conn.enable()
                
                # Now initiate connection to the target from the jumpbox
                target_host = self.target_params['host']
                target_username = self.target_params['username']
                
                print(f"Connecting to {target_host} via jump box...")
                print(f"Target username: '{target_username}'")
                
                if not target_username or target_username.strip() == '':
                    print("ERROR: Target username is empty! This will cause the SSH command to fail.")
                    target_username = input("Please enter the target username: ")
                    self.target_params['username'] = target_username
                
                # Use the jumpbox to connect to the target
                ssh_cmd = f"ssh -l {target_username} {target_host}"
                print(f"Executing: {ssh_cmd}")
                
                self.jumpbox_conn.write_channel(f"{ssh_cmd}\n")
                time.sleep(3)  # Give more time for SSH to establish
                
                # Check for password prompt and send password
                output = self.jumpbox_conn.read_channel()
                print(f"Initial response: {output}")
                
                if "assword" in output:
                    print(f"Password prompt detected, sending password for {target_username}")
                    self.jumpbox_conn.write_channel(f"{self.target_params['password']}\n")
                    time.sleep(2)
                    
                    # Read again to check if we're connected
                    output = self.jumpbox_conn.read_channel()
                    print(f"After password: {output}")
                
                # Verify we're connected to the target by sending a newline
                self.jumpbox_conn.write_channel("\n")
                time.sleep(1)
                output = self.jumpbox_conn.read_channel()
                print(f"Connection check output: {output}")
                
                if "#" in output or ">" in output:
                    print(f"Successfully connected to {target_host}")
                    
                    # Disable pagination to get full command output
                    print("Disabling command pagination...")
                    self.jumpbox_conn.write_channel("terminal length 0\n")
                    time.sleep(1)
                    self.jumpbox_conn.read_channel()  # Clear the output
                    
                    # Set terminal width to avoid line wrapping
                    self.jumpbox_conn.write_channel("terminal width 0\n")
                    time.sleep(1)
                    self.jumpbox_conn.read_channel()  # Clear the output
                    
                    self.connected = True
                    return True
                else:
                    print(f"Connection to {target_host} appears to have failed. Output: {output}")
                    raise Exception(f"Failed to connect to target {target_host} via jumpbox")
            
            def send_command(self, command, expect_string=None, read_timeout=180, verbose=False):
                """
                Send a command and capture the complete output.
                This function is designed to reliably capture all output regardless of length.
                
                Args:
                    command: The command to execute
                    expect_string: String to expect in output to consider command complete
                    read_timeout: Maximum time to wait for command completion
                    verbose: Whether to print detailed status messages
                """
                if not self.connected or not self.jumpbox_conn:
                    self.connect()
                
                # Clear any pending data in the buffer
                if self.jumpbox_conn.remote_conn.recv_ready():
                    buffer_data = self.jumpbox_conn.read_channel()
                    if verbose:
                        print(f"Cleared buffer before command: {buffer_data}")
                
                # Clean up the command
                clean_command = command.strip()
                
                # Send the command to the target device
                if verbose:
                    print(f"Sending command to target: '{clean_command}'")
                
                # Add a leading space to prevent first character loss due to line issues
                self.jumpbox_conn.write_channel(f" {clean_command}\n")
                time.sleep(0.1)  # Small delay after sending command
                # Send a backspace to remove the leading space
                self.jumpbox_conn.write_channel("\b")
                
                # Allow time for command to start processing
                time.sleep(1.0)
                
                # Initialize result collection
                result = ""
                timeout_counter = read_timeout
                read_interval = 0.1
                last_data_time = time.time()
                
                # Define markers
                terminal_markers = ["#", ">", "$ "]
                more_prompts = ["--More--", " --More-- ", "---More---"]
                handling_pagination = False
                
                if verbose:
                    print(f"Reading output for command: '{clean_command}'")
                
                # Main output collection loop
                while timeout_counter > 0:
                    if self.jumpbox_conn.remote_conn.recv_ready():
                        new_data = self.jumpbox_conn.read_channel()
                        if new_data:
                            result += new_data
                            last_data_time = time.time()
                            
                            # Handle pagination if detected
                            if any(more_prompt in new_data for more_prompt in more_prompts):
                                if verbose:
                                    print(f"Detected pagination prompt, sending space to continue")
                                handling_pagination = True
                                self.jumpbox_conn.write_channel(" ")
                                time.sleep(0.5)  # Give time for next page
                                continue
                            
                            # Check for expected string
                            if expect_string and expect_string in result:
                                if verbose:
                                    print(f"Found expect_string, completing command")
                                break
                                
                            # Check for prompt at the END of output (not in the middle)
                            # This is critical for accurate detection of command completion
                            if not handling_pagination:
                                lines = result.splitlines()
                                if lines:
                                    last_line = lines[-1].strip()
                                    if any(last_line.endswith(marker) for marker in terminal_markers):
                                        if verbose:
                                            print(f"Found command prompt at end of output, completing command")
                                        break
                                
                            # Reset pagination flag if we've moved past it
                            if handling_pagination and not any(more_prompt in new_data for more_prompt in more_prompts):
                                handling_pagination = False
                    else:
                        # No data available, wait a bit
                        time.sleep(read_interval)
                        timeout_counter -= read_interval
                        
                        # If we haven't received data for a while and NOT in pagination mode
                        if result and not handling_pagination and (time.time() - last_data_time) > 2.0:
                            # Double-check to make sure we've reached the end by looking for a prompt
                            lines = result.splitlines()
                            if lines:
                                last_line = lines[-1].strip()
                                if any(marker in last_line for marker in terminal_markers):
                                    if verbose:
                                        print(f"No new data for 2 seconds, found end marker, completing command")
                                    break
                                else:
                                    # If no prompt found yet, give it more time
                                    if verbose:
                                        print(f"No new data for 2 seconds, but no end marker yet. Reading more...")
                                    # To avoid repeated messages, reset the timer
                                    last_data_time = time.time()
                            else:
                                # No lines yet, keep waiting
                                last_data_time = time.time()
                
                # Final check for any remaining data
                for _ in range(3):
                    if self.jumpbox_conn.remote_conn.recv_ready():
                        new_data = self.jumpbox_conn.read_channel()
                        if new_data:
                            result += new_data
                    time.sleep(0.5)
                
                # Clean up the output
                result_lines = result.splitlines()
                if len(result_lines) > 1:
                    # Remove command echo from the first few lines
                    for i in range(min(3, len(result_lines))):
                        if clean_command in result_lines[i]:
                            result_lines.pop(i)
                            break
                    clean_result = "\n".join(result_lines)
                else:
                    clean_result = result
                
                # Remove pagination artifacts
                for more_prompt in more_prompts:
                    clean_result = clean_result.replace(more_prompt, "")
                
                if verbose:
                    print(f"Command completed in {read_timeout - timeout_counter:.1f} seconds, result length: {len(clean_result)} bytes")
                return clean_result
            
            def disconnect(self):
                if self.jumpbox_conn:
                    # Exit from target device first
                    print("Disconnecting from target device...")
                    self.jumpbox_conn.write_channel("exit\n")
                    time.sleep(1)
                    
                    # Check if we've returned to the jump box prompt
                    output = self.jumpbox_conn.read_channel()
                    print(f"After exiting target: {output}")
                    
                    # Then close jumpbox connection
                    print("Disconnecting from jump box...")
                    self.jumpbox_conn.disconnect()
                    self.connected = False
        
        # Create the Cisco jumpbox proxy
        # For authentication, we need to ensure we're using the actual credentials, not variable names
        cisco_proxy = CiscoJumpBoxProxy(
            jumpbox_params={
                'device_type': jumpbox_type,
                'host': jumpbox_host,
                'username': jumpbox_username,
                'password': jumpbox_password,
                'secret': jumpbox_secret,
                'port': jumpbox_port,
                'log_file': log_file
            },
            target_params={
                'host': host.hostname,
                'username': target_username,
                'password': target_password
            }
        )
        
        # Store the proxy in the host connection options
        host.connection_options['netmiko'].extras['cisco_proxy'] = cisco_proxy
        
        # Monkey patch the netmiko_send_command task for this specific host
        original_netmiko_send_command = netmiko_send_command
        
        def patched_netmiko_send_command(task, command_string, use_timing=False, enable=False, **kwargs):
            """Custom netmiko_send_command to use our Cisco proxy for this host."""
            if task.host.name == host.name:
                proxy = task.host.connection_options['netmiko'].extras.get('cisco_proxy')
                if proxy:
                    try:
                        # Connect if not already connected
                        if not proxy.connected:
                            proxy.connect()
                        
                        # Log the actual command being used
                        print(f"Executing command on {task.host.name} via Cisco jump box: {command_string}")
                        
                        # Performance optimization - batch commands if possible
                        # Some network commands can be slow, so we'll optimize by
                        # checking if this is a show command (safe to execute)
                        read_timeout = kwargs.get('read_timeout', 30)
                        
                        # Send the command via the Cisco proxy with optimized timeout
                        result = proxy.send_command(
                            command=command_string,
                            expect_string=kwargs.get('expect_string'),
                            read_timeout=read_timeout
                        )
                        
                        # Return the result in the same format Nornir expects
                        from nornir.core.task import Result
                        return Result(host=task.host, result=result)
                    except Exception as e:
                        from nornir.core.task import Result
                        return Result(host=task.host, result=str(e), failed=True)
            
            # Fall back to the original function for other hosts
            return original_netmiko_send_command(task, command_string, use_timing, enable, **kwargs)
        
        # Replace the function for this run
        globals()['netmiko_send_command'] = patched_netmiko_send_command
        
        print(f"Successfully configured {host.name} to connect via Cisco jump box using custom method")
        return True
    
    else:
        print(f"WARNING: Jump box type {jumpbox_type} is not supported.")
        return False

def transform_func(host, account):
    # Handle jump box configuration if defined in host data
    jumpbox = host.get('jumpbox', False)
    
    if jumpbox and isinstance(jumpbox, str):
        # Set jumpbox connection options
        if 'netmiko' not in host.connection_options:
            host.connection_options['netmiko'] = ConnectionOptions(
                extras={'session_log': f"/tmp/{host.name}_session.log"}
            )
            
        # Get jumpbox credentials and configuration from environment variables if available
        jumpbox_env_prefix = jumpbox  # Use the jumpbox identifier (e.g., 'JB1') as prefix
        
        # Check if environment variables are set; if not, prompt for them
        if jumpbox == 'JB1' and os.getenv(f'{jumpbox}_HOST', '') == '':
            print(f"Configuring jump box {jumpbox} credentials")
            # If environment variables are not set, prompt for values
            os.environ[f'{jumpbox}_TYPE'] = os.getenv(f'{jumpbox}_TYPE') or input(f"Jump box device type (linux, cisco_ios, cisco_xe, etc.): ")
            os.environ[f'{jumpbox}_HOST'] = os.getenv(f'{jumpbox}_HOST') or input(f"Jump box hostname: ")
            os.environ[f'{jumpbox}_USER'] = os.getenv(f'{jumpbox}_USER') or input(f"Jump box username: ")
            os.environ[f'{jumpbox}_PASS'] = os.getenv(f'{jumpbox}_PASS') or getpass(f"Jump box password: ")
            
            # For Cisco devices, we might need enable secret and port
            if os.environ[f'{jumpbox}_TYPE'] in ['cisco_ios', 'cisco_xe', 'cisco_nxos']:
                os.environ[f'{jumpbox}_SECRET'] = os.getenv(f'{jumpbox}_SECRET') or getpass(f"Jump box enable secret (leave empty if not needed): ")
                os.environ[f'{jumpbox}_PORT'] = os.getenv(f'{jumpbox}_PORT') or input(f"Jump box SSH port [22]: ") or "22"
        else:
            # Check if the required environment variables exist
            required_vars = [f'{jumpbox}_TYPE', f'{jumpbox}_HOST', f'{jumpbox}_USER', f'{jumpbox}_PASS']
            missing_vars = [var for var in required_vars if os.getenv(var, '') == '']
            
            if missing_vars:
                print(f"Missing required environment variables for {jumpbox}: {', '.join(missing_vars)}")
                for var in missing_vars:
                    if var == f'{jumpbox}_PASS':
                        os.environ[var] = getpass(f"Enter {var}: ")
                    else:
                        os.environ[var] = input(f"Enter {var}: ")
                
                # For Cisco devices, check additional variables
                if os.environ[f'{jumpbox}_TYPE'] in ['cisco_ios', 'cisco_xe', 'cisco_nxos']:
                    if f'{jumpbox}_SECRET' not in os.environ:
                        os.environ[f'{jumpbox}_SECRET'] = getpass(f"Jump box enable secret (leave empty if not needed): ")
                    if f'{jumpbox}_PORT' not in os.environ:
                        os.environ[f'{jumpbox}_PORT'] = input(f"Jump box SSH port [22]: ") or "22"
        
        print(f"Using jump box configuration from environment variables:")
        print(f"  Type: {os.environ.get(f'{jumpbox}_TYPE')}")
        print(f"  Host: {os.environ.get(f'{jumpbox}_HOST')}")
        print(f"  User: {os.environ.get(f'{jumpbox}_USER')}")
        print(f"  Port: {os.environ.get(f'{jumpbox}_PORT', '22')}")
        
        # Set up the jump box connection with our custom approach
        jumpbox_type = os.environ.get(f'{jumpbox}_TYPE', 'linux')
        
        # Handle device credentials before setting up the jumpbox
        # This ensures our credential resolution happens first
        if account == 'UN1' and os.getenv('UN1', '') == '':
            print("The UN1 environment variable is not initialized")
            os.environ['UN1'] = input("Username for UN1:")
            os.environ['PW1'] = getpass()
            host.password = os.environ.get('PW1','bogus')
            host.username = os.environ.get('UN1','bogus')
        elif account == 'UN1':
            host.password = os.environ.get('PW1','bogus')
            host.username = os.environ.get('UN1','bogus')
        elif account == 'UN2' and os.getenv('UN2', '') == '':
            print("The UN2 environment variable is not initialized")
            os.environ['UN2'] = input("Username for UN2:")
            os.environ['PW2'] = getpass()
            host.password = os.environ.get('PW2','bogus')
            host.username = os.environ.get('UN2','bogus')
        elif account == 'UN2':
            host.password = os.environ.get('PW2','bogus')
            host.username = os.environ.get('UN2','bogus')
        elif account == 'UN3' and os.getenv('UN3', '') == '':
            print("The UN3 environment variable is not initialized")
            os.environ['UN3'] = input("Username for UN3:")
            os.environ['PW3'] = getpass()
            host.password = os.environ.get('PW3','bogus')
            host.username = os.environ.get('UN3','bogus')
        elif account == 'UN3':
            host.password = os.environ.get('PW3','bogus')
            host.username = os.environ.get('UN3','bogus')
        elif account == 'UN4' and os.getenv('UN4', '') == '':
            print("The UN4 environment variable is not initialized")
            os.environ['UN4'] = input("Username for UN4:")
            os.environ['PW4'] = getpass()
            host.password = os.environ.get('PW4','bogus')
            host.username = os.environ.get('UN4','bogus')
        elif account == 'UN4':
            host.password = os.environ.get('PW4','bogus')
            host.username = os.environ.get('UN4','bogus')
        else:
            # Prompt for username and password
            print(f"Input Credentials for {host}")
            host.username = input("Username: ")
            host.password = getpass()
            
        # Now set up the jump box with the credentials already properly resolved
        setup_jumpbox_connection(jumpbox_type, host, account)
    else:
        # No jumpbox, just resolve credentials normally
        if account == 'UN1' and os.getenv('UN1', '') == '':
            print("The UN1 environment variable is not initialized")
            os.environ['UN1'] = input("Username for UN1:")
            os.environ['PW1'] = getpass()
            host.password = os.environ.get('PW1','bogus')
            host.username = os.environ.get('UN1','bogus')
        elif account == 'UN1':
            host.password = os.environ.get('PW1','bogus')
            host.username = os.environ.get('UN1','bogus')
        elif account == 'UN2' and os.getenv('UN2', '') == '':
            print("The UN2 environment variable is not initialized")
            os.environ['UN2'] = input("Username for UN2:")
            os.environ['PW2'] = getpass()
            host.password = os.environ.get('PW2','bogus')
            host.username = os.environ.get('UN2','bogus')
        elif account == 'UN2':
            host.password = os.environ.get('PW2','bogus')
            host.username = os.environ.get('UN2','bogus')
        elif account == 'UN3' and os.getenv('UN3', '') == '':
            print("The UN3 environment variable is not initialized")
            os.environ['UN3'] = input("Username for UN3:")
            os.environ['PW3'] = getpass()
            host.password = os.environ.get('PW3','bogus')
            host.username = os.environ.get('UN3','bogus')
        elif account == 'UN3':
            host.password = os.environ.get('PW3','bogus')
            host.username = os.environ.get('UN3','bogus')
        elif account == 'UN4' and os.getenv('UN4', '') == '':
            print("The UN4 environment variable is not initialized")
            os.environ['UN4'] = input("Username for UN4:")
            os.environ['PW4'] = getpass()
            host.password = os.environ.get('PW4','bogus')
            host.username = os.environ.get('UN4','bogus')
        elif account == 'UN4':
            host.password = os.environ.get('PW4','bogus')
            host.username = os.environ.get('UN4','bogus')
        else:
            # Prompt for username and password
            print(f"Input Credentials for {host}")
            host.username = input("Username: ")
            host.password = getpass()

if __name__ == "__main__":
    # Import required libraries for ConnectionOptions
    from nornir.core.inventory import ConnectionOptions

    # Command line arguments for filtering
    parser = argparse.ArgumentParser(description="A script that takes a variable value from the command line.")
    parser.add_argument("--function", help="An optional value", default="")
    parser.add_argument("--site", help="An optional value", default="")
    parser.add_argument("--update", help="An optional value", default="")
    parser.add_argument("--jumpbox", help="Specify a jump box for all connections (JB1, JB2, etc.)", default="")
    args = parser.parse_args()
    
    # Check for command line flag to rerun inventory file creation
    if args.update == "inv":
        createinventory.makefile()

    # Initialize Nornir with SimpleInventory
    InventoryPluginRegister.register("SimpleInventory", SimpleInventory)
    nr = InitNornir(config_file="/app/files/config.yaml")

    # Filter the inventory
    filtered_nr = filter_inventory(nr, site=args.site, function=args.function)
    
    # Apply global jumpbox setting if specified on command line
    if args.jumpbox:
        print(f"Using jump box {args.jumpbox} for all connections")
        for host in filtered_nr.inventory.hosts.values():
            host.data['jumpbox'] = args.jumpbox

    # Update the username and password in the filtered inventory
    for host in filtered_nr.inventory.hosts.values():
        host_key = str(host)
        account = filtered_nr.inventory.hosts[host_key].get('username')
        transform_func(host, account)

    #Make the ./output directory if not exist
    Path("/app/files/output").mkdir(parents=True, exist_ok=True)

    # Run commands based on 'cmds' attribute
    result = filtered_nr.run(task=run_commands)
    # Write the output to files
    filtered_nr.run(task=write_output, r=result)
    # Upload the files to Sharepoint
    upload = input("Would you like to upload the output files to sharepoint (y/n)")
    if upload == "y":
        upload_to_sharepoint.upload_files()
    else:
        print("All Done!")