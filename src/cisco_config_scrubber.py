#!/usr/bin/env python3
"""
Cisco Configuration Scrubber

This script scrubs sensitive information from Cisco router and switch configuration files,
including passwords, community strings, keys, and other sensitive data.

Usage:
    python cisco_config_scrubber.py [--input-dir DIR] [--output-dir DIR] [--mask-ips] [--mask-hostnames]
    
The script uses the following directory structure:
- ./src/              : Source code directory
- ./files/output/     : Original configuration files (input)
- ./files/scrubbed/   : Scrubbed configuration files (output)
- ./files/report/     : Output PDF reports
"""

import re
import sys
import os
import ipaddress
import argparse
from pathlib import Path
import glob


# Define project directory structure
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
FILES_DIR = PROJECT_ROOT / "files"
OUTPUT_DIR = FILES_DIR / "output"
SCRUBBED_DIR = FILES_DIR / "scrubbed"
REPORT_DIR = FILES_DIR / "report"

# Ensure all directories exist
for directory in [OUTPUT_DIR, SCRUBBED_DIR, REPORT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


class CiscoConfigScrubber:
    def __init__(self, mask_ips=False, mask_hostnames=False):
        """
        Initialize the Cisco configuration scrubber with options
        
        Args:
            mask_ips: If True, IP addresses will be masked
            mask_hostnames: If True, hostnames will be masked
        """
        self.mask_ips = mask_ips
        self.mask_hostnames = mask_hostnames
        
        # Counter for unique replacements
        self.hostname_counter = 1
        self.ip_counter = 1
        self.subnet_map = {}
        self.username_counter = 1
        self.username_map = {}
        
        # Patterns for sensitive information
        self.sensitive_patterns = [
            # Passwords and secrets
            (re.compile(r'(enable secret) .*$'), r'\1 <REMOVED>'),
            (re.compile(r'(enable password) .*$'), r'\1 <REMOVED>'),
            (re.compile(r'(username \S+) (password|secret) .*$'), r'\1 \2 <REMOVED>'),
            (re.compile(r'(password|secret) .*$'), r'\1 <REMOVED>'),
            
            # SNMP strings
            (re.compile(r'(snmp-server community) \S+'), r'\1 <REMOVED>'),
            (re.compile(r'(snmp-server host \S+) \S+'), r'\1 <REMOVED>'),
            
            # TACACS/RADIUS keys
            (re.compile(r'(tacacs-server key) .*$'), r'\1 <REMOVED>'),
            (re.compile(r'(radius-server key) .*$'), r'\1 <REMOVED>'),
            (re.compile(r'(key) \S+'), r'\1 <REMOVED>'),
            
            # SSH/Crypto keys
            (re.compile(r'(crypto key generate rsa).*$'), r'\1 <REMOVED>'),
            (re.compile(r'^.*ssh-(rsa|dss) .*$'), '<SSH-KEY-REMOVED>'),
            
            # Pre-shared keys
            (re.compile(r'(\s+pre-shared-key) .*$'), r'\1 <REMOVED>'),
            
            # IPSEC keys
            (re.compile(r'(\s+authentication pre-shared-key) .*$'), r'\1 <REMOVED>'),
            
            # VTY access lists
            (re.compile(r'(access-class) \S+'), r'\1 <REMOVED>'),
            
            # EIGRP/OSPF authentication keys
            (re.compile(r'(authentication key-string) .*$'), r'\1 <REMOVED>'),
            (re.compile(r'(ip ospf authentication-key) .*$'), r'\1 <REMOVED>'),
            
            # BGP passwords
            (re.compile(r'(neighbor \S+ password) .*$'), r'\1 <REMOVED>'),
            
            # General service passwords
            (re.compile(r'(\s+password) \S+'), r'\1 <REMOVED>'),
            
            # Certificate information
            (re.compile(r'^\s*certificate .*$'), ' certificate <REMOVED>'),
            
            # Private keys in config
            (re.compile(r'^\s*(key-string|private-key)(\s+.*)?$', re.DOTALL), r'\1 <REMOVED>'),
        ]

    def _mask_ip(self, match):
        """
        Replace IP address with a masked version while maintaining subnet structure.
        Preserves subnet masks (addresses starting with 255).
        Only changes first two octets of other IP addresses.
        """
        ip_str = match.group(0)
        
        # Skip subnet masks (IPs starting with 255)
        if ip_str.startswith('255'):
            return ip_str
        
        try:
            # Check if it has a subnet part
            if '/' in ip_str:
                ip_addr, subnet = ip_str.split('/')
                subnet = int(subnet)
                
                # If the IP part starts with 255, don't change it
                if ip_addr.startswith('255'):
                    return ip_str
                
                # Split the IP address into octets
                octets = ip_addr.split('.')
                if len(octets) == 4:  # IPv4
                    # Only mask the first two octets
                    masked_ip = f"10.{self.ip_counter}.{octets[2]}.{octets[3]}/{subnet}"
                    self.ip_counter += 1
                    return masked_ip
                
                return ip_str  # Return unchanged if not IPv4
                
            # For single IP addresses
            ip_obj = ipaddress.ip_address(ip_str)
            
            if ip_obj.version == 4:
                # Split into octets
                octets = ip_str.split('.')
                if len(octets) == 4:
                    # Only mask the first two octets
                    masked_ip = f"10.{self.ip_counter}.{octets[2]}.{octets[3]}"
                    self.ip_counter += 1
                    return masked_ip
                    
                return ip_str  # Return unchanged if not expected format
            else:  # IPv6
                return f"2001:db8::{self.ip_counter}"
        except ValueError:
            # If we can't parse the IP, just return it unchanged
            return ip_str

    def _mask_fqdn(self, match):
        """Replace FQDNs with example.com domain"""
        fqdn = match.group(0)
        
        # Split the FQDN into parts
        parts = fqdn.split('.')
        
        # Keep the hostname/subdomain, but change the domain to example.com
        if len(parts) >= 2:
            # Preserve the subdomains but replace the top-level domain
            return '.'.join(parts[:-2] + ['example', 'com'])
        
        # If it's not a proper FQDN, return unchanged
        return fqdn
        
    def _mask_username(self, match):
        """Replace username with a generic dummy value"""
        username = match.group(1)  # The captured username
        
        # Check if we've seen this username before
        if username not in self.username_map:
            self.username_map[username] = f"user{self.username_counter}"
            self.username_counter += 1
            
        # Return the replacement username plus the rest of the match
        return f"username {self.username_map[username]}{match.group(2)}"

    def scrub_config(self, config_text):
        """
        Scrub sensitive information from the provided configuration text
        
        Args:
            config_text: The Cisco configuration text to scrub
            
        Returns:
            The scrubbed configuration text
        """
        scrubbed_text = config_text
        
        # Apply all the regex patterns
        for pattern, replacement in self.sensitive_patterns:
            scrubbed_text = pattern.sub(replacement, scrubbed_text)
        
        # Handle username scrubbing
        username_pattern = re.compile(r'(username\s+)(\S+)(.*)')
        scrubbed_text = username_pattern.sub(lambda m: f"{m.group(1)}user{self.username_counter}{m.group(3)}", scrubbed_text)
        
        # Increment username counter for each unique username
        self.username_counter += 1
            
        # Handle hostname scrubbing if enabled
        if self.mask_hostnames:
            hostname_pattern = re.compile(r'(hostname) (\S+)')
            scrubbed_text = hostname_pattern.sub(rf'\1 ROUTER{self.hostname_counter}', scrubbed_text)
            self.hostname_counter += 1
        
        # Handle IP address scrubbing if enabled
        if self.mask_ips:
            # Match both IPv4 and IPv6 addresses
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?|[0-9a-fA-F:]+:[0-9a-fA-F:]*)\b')
            scrubbed_text = ip_pattern.sub(lambda m: self._mask_ip(m), scrubbed_text)
        
        # Handle FQDN scrubbing (domains to example.com)
        fqdn_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        scrubbed_text = fqdn_pattern.sub(lambda m: self._mask_fqdn(m), scrubbed_text)
            
        return scrubbed_text

    def process_directory(self, input_dir, output_dir, mask_ips=False, mask_hostnames=False):
        """
        Process all configuration files in a directory
        
        Args:
            input_dir: Directory containing input configuration files
            output_dir: Directory to write scrubbed configuration files
            mask_ips: Whether to mask IP addresses
            mask_hostnames: Whether to mask hostnames
            
        Returns:
            List of paths to scrubbed files
        """
        self.mask_ips = mask_ips
        self.mask_hostnames = mask_hostnames
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Find all text files in the input directory
        input_files = glob.glob(os.path.join(input_dir, "*.txt"))
        input_files.extend(glob.glob(os.path.join(input_dir, "*.cfg")))
        input_files.extend(glob.glob(os.path.join(input_dir, "*.conf")))
        
        if not input_files:
            print(f"No configuration files found in {input_dir}")
            return []
        
        scrubbed_files = []
        
        for input_file in input_files:
            # Determine output filename
            filename = os.path.basename(input_file)
            base, ext = os.path.splitext(filename)
            output_file = os.path.join(output_dir, f"{base}_scrubbed{ext}")
            
            try:
                # Read input file
                with open(input_file, 'r') as f:
                    config_text = f.read()
                
                # Scrub the configuration
                scrubbed_text = self.scrub_config(config_text)
                
                # Write output file
                with open(output_file, 'w') as f:
                    f.write(scrubbed_text)
                
                print(f"Scrubbed {input_file} -> {output_file}")
                scrubbed_files.append(output_file)
                
            except Exception as e:
                print(f"Error processing {input_file}: {str(e)}")
        
        return scrubbed_files

def main():
    parser = argparse.ArgumentParser(description='Scrub sensitive information from Cisco configurations')
    parser.add_argument('--input-dir', default=str(OUTPUT_DIR),
                        help=f'Directory containing input configuration files (default: {OUTPUT_DIR})')
    parser.add_argument('--output-dir', default=str(SCRUBBED_DIR),
                        help=f'Directory to write scrubbed configuration files (default: {SCRUBBED_DIR})')
    parser.add_argument('--mask-ips', action='store_true', help='Mask IP addresses')
    parser.add_argument('--mask-hostnames', action='store_true', help='Mask hostnames')
    parser.add_argument('input_file', nargs='?', default=None, help='Single input file to process (optional)')
    parser.add_argument('output_file', nargs='?', default=None, help='Single output file (optional)')
    
    args = parser.parse_args()
    
    # Create scrubber
    scrubber = CiscoConfigScrubber(mask_ips=args.mask_ips, mask_hostnames=args.mask_hostnames)
    
    # Process a single file if specified
    if args.input_file:
        if not os.path.isfile(args.input_file):
            print(f"Error: Input file '{args.input_file}' not found.")
            sys.exit(1)
        
        # Determine output filename if not specified
        if args.output_file:
            output_file = args.output_file
        else:
            input_path = Path(args.input_file)
            output_file = str(SCRUBBED_DIR / f"{input_path.stem}_scrubbed{input_path.suffix}")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        try:
            # Read input file
            with open(args.input_file, 'r') as f:
                config_text = f.read()
            
            # Scrub the configuration
            scrubbed_text = scrubber.scrub_config(config_text)
            
            # Write output file
            with open(output_file, 'w') as f:
                f.write(scrubbed_text)
            
            print(f"\nSuccess! Scrubbed configuration saved to '{output_file}'")
            
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
    
    # Process directory
    else:
        scrubbed_files = scrubber.process_directory(
            args.input_dir, 
            args.output_dir,
            mask_ips=args.mask_ips,
            mask_hostnames=args.mask_hostnames
        )
        
        if scrubbed_files:
            print(f"\nSuccess! Scrubbed {len(scrubbed_files)} configuration files.")
        else:
            print("\nNo files were scrubbed.")

if __name__ == "__main__":
    main()
