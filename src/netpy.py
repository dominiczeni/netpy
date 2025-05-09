#!/usr/bin/env python3
from nornir import InitNornir
from nornir.plugins.inventory import SimpleInventory
from nornir.core.plugins.inventory import InventoryPluginRegister
from nornir_utils.plugins.tasks.files import write_file
from getpass import getpass
from datetime import datetime
from pathlib import Path
from nornir.core.filter import F
from nornir_netmiko.tasks import netmiko_send_command, netmiko_send_config, netmiko_save_config
from nornir_utils.plugins.functions import print_result
import argparse
import sys
import os
import createinventory
import upload_to_sharepoint
import subprocess
import paramiko
import time
from nornir.core.inventory import ConnectionOptions


# Global verbose flag
VERBOSE = False

def get_verbose():
    """Get the verbose setting"""
    return VERBOSE


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

def send_config_commands(task, commands):
    """
    Send config commands to devices and save the configuration
    """
    # Check verbosity setting
    verbose = get_verbose()
    
    # Check if host uses a Cisco proxy (for jumpbox connectivity)
    has_cisco_proxy = False
    if hasattr(task.host, 'connection_options') and 'netmiko' in task.host.connection_options:
        if 'cisco_proxy' in task.host.connection_options['netmiko'].extras:
            has_cisco_proxy = True
    
    # For hosts using Cisco proxy, we handle this differently - commands are already sent by the proxy
    if has_cisco_proxy:
        # The commands are handled by the patched netmiko_send_config function
        # which works with the Cisco proxy directly
        result = task.run(
            task=netmiko_send_config,
            config_commands=commands,
            name=f"Applying configuration"
        )
    else:
        # For standard (non-proxy) connections, we need to handle each command manually
        # to ensure proper prompt display and confirmation handling
        from nornir.core.task import Result
        from netmiko.exceptions import ReadTimeout
        import re

        # Get direct connection to the device
        try:
            conn = task.host.get_connection('netmiko', task.nornir.config)
            
            # First get the device prompt
            conn.find_prompt()
            base_prompt = conn.base_prompt
            
            # Enter configuration mode
            config_prompt = conn.config_mode()
            
            # Store command outputs
            command_outputs = []
            
            # Now manually send each command and handle any confirmations
            for cmd in commands:
                if verbose:
                    print(f"Sending config command to {task.host.name}: {cmd}")
                
                # First get a clean prompt
                conn.write_channel("\n")
                time.sleep(0.5)
                
                # Clear any output
                if conn.remote_conn.recv_ready():
                    conn.read_channel()
                
                # Now write the command (without newline) to make it appear after the prompt
                conn.write_channel(cmd)
                # Now send the enter key
                time.sleep(0.1)
                conn.write_channel("\n")
                
                # Wait for command to process
                time.sleep(1)
                
                # Read output and check for confirmations
                output = conn.read_channel()
                
                # Look for confirmation prompts
                confirmation_patterns = ["[confirm]", "? [yes/no]:", "? [y/n]:", "(y/n)", "[yes/no]", "continue?"]
                if any(pattern in output for pattern in confirmation_patterns):
                    if verbose:
                        print(f"Confirmation prompt detected for command: {cmd} - sending 'y'")
                    conn.write_channel("y\n")
                    time.sleep(1.5)
                    # Read additional output after confirmation
                    additional_output = conn.read_channel()
                    output += additional_output
                
                # Process the output to format commands correctly
                # Replace newlines between prompt and command with nothing to join them
                # This makes the command appear on the same line as the prompt
                output_lines = output.splitlines()
                for i in range(len(output_lines)-1):
                    # Check if this line ends with config prompt and next line is our command
                    if output_lines[i].endswith("(config)#") and cmd in output_lines[i+1]:
                        # Join this prompt with the command
                        output_lines[i] = output_lines[i] + cmd
                        # Remove the command-only line
                        output_lines[i+1] = ""
                
                # Rebuild output with cleaned up lines
                cleaned_output = "\n".join([line for line in output_lines if line])
                command_outputs.append(cleaned_output)
            
            # Exit config mode
            conn.exit_config_mode()
            
            # Build the result
            result_output = f"{config_prompt}\n" + "\n".join(command_outputs)
            result = Result(host=task.host, result=result_output, changed=True)
            
        except Exception as e:
            if verbose:
                print(f"Error configuring {task.host.name}: {str(e)}")
            result = Result(host=task.host, result=f"Error: {str(e)}", failed=True)
    
    # Save the configuration (no matter which method was used)
    task.run(
        task=netmiko_save_config,
        name=f"Saving configuration"
    )
    
    return result

def setup_jumpbox_connection(jumpbox_type, host, account):
    """
    Set up the jumpbox connection for a host using Paramiko directly.
    This avoids using proxy_jump_host parameter which appears to be problematic.
    """
    verbose = get_verbose()
    
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
        if 'netmiko' not in host.connection_options:
            host.connection_options['netmiko'] = ConnectionOptions(extras={})
        host.connection_options['netmiko'].extras['_proxy_client'] = proxy
        host.connection_options['netmiko'].extras['sock'] = channel
        
        print(f"Successfully configured {host.name} to connect via {jumpbox_type} jump box")
        return True
        
    # For Cisco jumpboxes, we create a custom solution
    elif jumpbox_type in ['cisco_ios', 'cisco_xe', 'cisco_nxos']:
        jumpbox_secret = os.environ.get('JB1_SECRET', '')
        
        # Create a session log file for debugging
        log_file = f"/tmp/{host.name}_jumpbox_session.log"
        if 'netmiko' not in host.connection_options:
            host.connection_options['netmiko'] = ConnectionOptions(extras={})
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
                # Get verbose setting
                verbose = get_verbose()
                
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
                
                # Parse command line arguments
                verbose = self.jumpbox_params.get('verbose', False)
                global_verbose = get_verbose()
                
                # Use local verbose or global verbose setting
                verbose = verbose or global_verbose
                
                # Now initiate connection to the target from the jumpbox
                target_host = self.target_params['host']
                target_username = self.target_params['username']
                
                # Only show detailed connection info in verbose mode
                if verbose:
                    print(f"Connecting to {target_host} via jump box...")
                    print(f"Target username: '{target_username}'")
                else:
                    print(f"Connecting to {target_host}...")
                
                if not target_username or target_username.strip() == '':
                    print("ERROR: Target username is empty! This will cause the SSH command to fail.")
                    target_username = input("Please enter the target username: ")
                    self.target_params['username'] = target_username
                
                # Use the jumpbox to connect to the target
                ssh_cmd = f"ssh -l {target_username} {target_host}"
                if verbose:
                    print(f"Executing: {ssh_cmd}")
                
                self.jumpbox_conn.write_channel(f"{ssh_cmd}\n")
                time.sleep(3)  # Give more time for SSH to establish
                
                # Check for password prompt and send password
                output = self.jumpbox_conn.read_channel()
                if verbose:
                    print(f"Initial response: {output}")
                
                if "assword" in output:
                    if verbose:
                        print(f"Password prompt detected, sending password for {target_username}")
                    self.jumpbox_conn.write_channel(f"{self.target_params['password']}\n")
                    time.sleep(2)
                    
                    # Read again to check if we're connected
                    output = self.jumpbox_conn.read_channel()
                    if verbose:
                        print(f"After password: {output}")
                
                # Verify we're connected to the target by sending a newline
                self.jumpbox_conn.write_channel("\n")
                time.sleep(1)
                output = self.jumpbox_conn.read_channel()
                if verbose:
                    print(f"Connection check output: {output}")
                
                if "#" in output or ">" in output:
                    if verbose:
                        print(f"Successfully connected to {target_host}")
                    
                    # Disable pagination to get full command output
                    if verbose:
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
                'log_file': log_file,
                'verbose': get_verbose()  # Get verbose flag from global setting
            },
            target_params={
                'host': host.hostname,
                'username': target_username,
                'password': target_password
            }
        )
        
        # Store the proxy in the host connection options - as a extras
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
                        verbose = get_verbose()
                        if verbose:
                            print(f"Executing command on {task.host.name} via Cisco jump box: {command_string}")
                        
                        # Performance optimization - batch commands if possible
                        # Some network commands can be slow, so we'll optimize by
                        # checking if this is a show command (safe to execute)
                        read_timeout = kwargs.get('read_timeout', 30)
                        
                        # Send the command via the Cisco proxy with optimized timeout
                        result = proxy.send_command(
                            command=command_string,
                            expect_string=kwargs.get('expect_string'),
                            read_timeout=read_timeout,
                            verbose=kwargs.get('verbose', False)
                        )
                        
                        # Return the result in the same format Nornir expects
                        from nornir.core.task import Result
                        return Result(host=task.host, result=result)
                    except Exception as e:
                        from nornir.core.task import Result
                        return Result(host=task.host, result=str(e), failed=True)
            
            # Fall back to the original function for other hosts
            return original_netmiko_send_command(task, command_string, use_timing, enable, **kwargs)
        
        # Patch for netmiko_send_config
        original_netmiko_send_config = netmiko_send_config
        
        def patched_netmiko_send_config(task, config_commands=None, config_file=None, enable=True, dry_run=None, **kwargs):
            """Custom netmiko_send_config to use our Cisco proxy for this host."""
            # Get verbose setting
            verbose = get_verbose()
            
            if task.host.name == host.name:
                proxy = task.host.connection_options['netmiko'].extras.get('cisco_proxy')
                if proxy:
                    try:
                        # Connect if not already connected
                        if not proxy.connected:
                            proxy.connect()
                        
                        # Enter configuration mode
                        if verbose:
                            print(f"Entering configuration mode on {task.host.name} via Cisco jump box")
                        proxy.jumpbox_conn.write_channel("configure terminal\n")
                        time.sleep(2)  # Increase wait time for slower devices
                        
                        # Read and store the output, but don't require a specific pattern
                        output = proxy.jumpbox_conn.read_channel()
                        if verbose:
                            print(f"Config mode response: {output}")
                        
                        # Send a blank line to check response
                        proxy.jumpbox_conn.write_channel("\n")
                        time.sleep(1)
                        check_output = proxy.jumpbox_conn.read_channel()
                        
                        # Proceed regardless of what we see
                        if verbose:
                            print(f"Ready to send configuration commands to {task.host.name}")
                        
                        # Apply each configuration command
                        results = []
                        for cmd in config_commands:
                            # Wait briefly to ensure prompt stability
                            time.sleep(0.5)
                            
                            # First, read any pending output to clear the buffer
                            if proxy.jumpbox_conn.remote_conn.recv_ready():
                                buffer_data = proxy.jumpbox_conn.read_channel()
                            
                            if verbose:
                                print(f"Sending config command to {task.host.name}: {cmd}")
                            
                            # First get the prompt
                            proxy.jumpbox_conn.write_channel("\n")
                            time.sleep(0.5)
                            prompt = proxy.jumpbox_conn.read_channel().strip()
                            
                            # Now send the command directly after the prompt
                            # Only write the cmd to the display, don't add a newline yet
                            # This simulates typing the command after the prompt
                            proxy.jumpbox_conn.write_channel(cmd)
                            # Only now send the Enter key to execute the command
                            time.sleep(0.1)
                            proxy.jumpbox_conn.write_channel("\n")
                            
                            time.sleep(1.5)  # Give time for the command to execute
                            
                            # Check for confirmation prompts and handle them
                            output = proxy.jumpbox_conn.read_channel()
                            
                            # Process the output to join prompt and command
                            output_lines = output.splitlines()
                            for i in range(len(output_lines)-1):
                                # Check if this line ends with config prompt and next line is our command
                                if output_lines[i].endswith("(config)#") and cmd in output_lines[i+1]:
                                    # Join this prompt with the command
                                    output_lines[i] = output_lines[i] + cmd
                                    # Remove the command-only line
                                    output_lines[i+1] = ""
                            
                            # Rebuild output with cleaned up lines and no empty lines
                            output = "\n".join([line for line in output_lines if line])
                            
                            # Handle various confirmation prompt patterns
                            confirmation_patterns = ["[confirm]", "? [yes/no]:", "? [y/n]:", "(y/n)", "[yes/no]", "yes/no", "continue?"]
                            if any(pattern in output for pattern in confirmation_patterns):
                                if verbose:
                                    print(f"Confirmation prompt detected for command: {cmd} - sending 'y'")
                                # Send 'y' to confirm
                                proxy.jumpbox_conn.write_channel("y\n")
                                time.sleep(1.5)
                                additional_output = proxy.jumpbox_conn.read_channel()
                                output += additional_output
                                
                            results.append(output)
                        
                        # Exit configuration mode
                        proxy.jumpbox_conn.write_channel("end\n")
                        time.sleep(1)
                        proxy.jumpbox_conn.read_channel()
                        
                        # Return the result in the same format Nornir expects
                        from nornir.core.task import Result
                        
                        # Process the results to clean up the format (join prompt+command)
                        processed_results = []
                        for result in results:
                            # Split into lines
                            lines = result.splitlines()
                            processed_lines = []
                            i = 0
                            while i < len(lines):
                                if i < len(lines)-1 and lines[i].endswith("(config)#") and not lines[i+1].startswith("DOMINIC"):
                                    # This is a prompt followed by a command
                                    processed_lines.append(lines[i] + lines[i+1])
                                    i += 2
                                else:
                                    processed_lines.append(lines[i])
                                    i += 1
                            processed_results.append("\n".join(processed_lines))
                        
                        return Result(host=task.host, result="\n".join(processed_results), changed=True)
                    except Exception as e:
                        from nornir.core.task import Result
                        return Result(host=task.host, result=str(e), failed=True)
            
            # Remove any Netmiko parameters that aren't supported
            if 'expect_string' in kwargs:
                del kwargs['expect_string']
                
            # Fall back to the original function for other hosts
            return original_netmiko_send_config(task, config_commands, config_file, enable, dry_run, **kwargs)
        
        # Patch for netmiko_save_config
        original_netmiko_save_config = netmiko_save_config
        
        def patched_netmiko_save_config(task, cmd="", confirm=False, confirm_response="", **kwargs):
            """Custom netmiko_save_config to use our Cisco proxy for this host."""
            # Get verbose setting
            verbose = get_verbose()
            
            if task.host.name == host.name:
                proxy = task.host.connection_options['netmiko'].extras.get('cisco_proxy')
                if proxy:
                    try:
                        # Connect if not already connected
                        if not proxy.connected:
                            proxy.connect()
                        
                        # Determine the right save command based on platform
                        save_cmd = cmd
                        if not save_cmd:
                            platform = task.host.platform
                            if platform in ['cisco_ios', 'cisco_xe']:
                                save_cmd = "write memory"
                            elif platform == 'cisco_nxos':
                                save_cmd = "copy running-config startup-config"
                            else:
                                save_cmd = "write memory"  # Default
                        
                        # Only show save message in verbose mode
                        if verbose:
                            print(f"Saving configuration on {task.host.name} via Cisco jump box: {save_cmd}")
                        
                        # Send the save command
                        proxy.jumpbox_conn.write_channel(f"{save_cmd}\n")
                        time.sleep(1)
                        
                        # Handle confirmation if needed
                        output = proxy.jumpbox_conn.read_channel()
                        if confirm or (confirm_response and "confirm" in output.lower()) or "[confirm]" in output:
                            response = confirm_response if confirm_response else "y"
                            if verbose:
                                print(f"Confirmation prompt detected, sending '{response}'")
                            proxy.jumpbox_conn.write_channel(f"{response}\n")
                            time.sleep(2)
                            output += proxy.jumpbox_conn.read_channel()
                        
                        # Wait for command to complete
                        timeout = 30
                        while timeout > 0 and not ("#" in output or ">" in output):
                            time.sleep(1)
                            timeout -= 1
                            if proxy.jumpbox_conn.remote_conn.recv_ready():
                                output += proxy.jumpbox_conn.read_channel()
                        
                        # Return the result
                        from nornir.core.task import Result
                        return Result(host=task.host, result=output, changed=True)
                    except Exception as e:
                        from nornir.core.task import Result
                        return Result(host=task.host, result=str(e), failed=True)
            
            # Fall back to the original function for other hosts
            return original_netmiko_save_config(task, cmd, confirm, confirm_response, **kwargs)
        
        # Replace the functions for this run
        globals()['netmiko_send_command'] = patched_netmiko_send_command
        globals()['netmiko_send_config'] = patched_netmiko_send_config
        globals()['netmiko_save_config'] = patched_netmiko_save_config
        
        print(f"Successfully configured {host.name} to connect via Cisco jump box using custom method")
        return True
    
    else:
        print(f"WARNING: Jump box type {jumpbox_type} is not supported.")
        return False

def transform_func(host, account):
    # Get verbose mode
    verbose = get_verbose()
    
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
    # Command line arguments for filtering
    parser = argparse.ArgumentParser(description="Network automation tool for commands and configuration.")
    parser.add_argument("--function", help="Filter devices by function", default="")
    parser.add_argument("--site", help="Filter devices by site", default="")
    parser.add_argument("--update", help="Update inventory file", default="")
    parser.add_argument("--send-config", help="Send configuration commands to devices", action="store_true")
    parser.add_argument("--jumpbox", help="Specify a jump box for all connections (JB1, JB2, etc.)", default="")
    parser.add_argument("--verbose", help="Show detailed connection and command information", action="store_true")
    args = parser.parse_args()
    
    # Set global verbose flag
    VERBOSE = args.verbose
    
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

    # Make sure we have hosts after filtering
    if len(filtered_nr.inventory.hosts) == 0:
        print("No hosts match the specified filters. Exiting.")
        sys.exit(1)

    # Update the username and password in the filtered inventory
    for host in filtered_nr.inventory.hosts.values():
        host_key = str(host)
        account = filtered_nr.inventory.hosts[host_key].get('username')
        transform_func(host, account)

    # Make the ./output directory if not exist
    Path("/app/files/output").mkdir(parents=True, exist_ok=True)

    # Handle send-config flag
    if args.send_config:
        # Display target devices to user
        print("\nTarget devices for configuration:")
        for i, host in enumerate(filtered_nr.inventory.hosts, 1):
            print(f"{i}. {host} ({filtered_nr.inventory.hosts[host].hostname})")
        
        print("\nEnter configuration commands (one per line). Enter an empty line when done:")
        config_commands = []
        while True:
            command = input("> ")
            if not command:
                break
            config_commands.append(command)
        
        if not config_commands:
            print("No configuration commands provided. Exiting.")
            sys.exit(0)
        
        # Show commands for confirmation
        print("\nCommands to be applied:")
        for i, cmd in enumerate(config_commands, 1):
            print(f"{i}. {cmd}")
        
        confirm = input("\nDo you want to apply these configurations to all listed devices? (y/n): ")
        if confirm.lower() not in ['y', 'yes']:
            print("Configuration cancelled. Exiting.")
            sys.exit(0)
        
        # Run configuration commands and save config
        result = filtered_nr.run(task=send_config_commands, commands=config_commands)
        print_result(result)
        print("All Done!")
    else:
        # Run regular commands based on 'commands' attribute
        result = filtered_nr.run(task=run_commands)
        # Write the output to files
        filtered_nr.run(task=write_output, r=result)
        
        # Ask about uploading to SharePoint only after write_output is run
        upload = input("Would you like to upload the output files to sharepoint (y/n): ")
        if upload.lower() in ['y', 'yes']:
            upload_to_sharepoint.upload_files()
        else:
            print("All Done!")
