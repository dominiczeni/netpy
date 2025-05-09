#!/usr/bin/env python3
"""
Configuration Parser Script

This script parses network device configuration files and extracts interface information
into a CSV file with the following columns:
- Hostname
- Location
- Interface
- Interface Description
- Mode
- VLAN
- Native VLAN
- Allowed VLANs
"""

import os
import csv
import re
from pathlib import Path

def extract_hostname(config_text):
    """Extract hostname from configuration text."""
    hostname_match = re.search(r'hostname\s+(\S+)', config_text)
    return hostname_match.group(1) if hostname_match else 'Unknown'

def extract_location(hostname):
    """Extract location from hostname (first two characters)."""
    return hostname[:2] if len(hostname) >= 2 else 'Unknown'

def parse_interface_config(config_text):
    """Parse interface configurations from the config text."""
    interfaces = []
    
    # Split the config into interface blocks
    interface_blocks = re.split(r'^interface\s+', config_text, flags=re.MULTILINE)
    
    # Skip the first split as it's the pre-interface configuration
    for block in interface_blocks[1:]:
        # Extract interface name (first line of the block)
        interface_name = block.split('\n')[0].strip()
        
        # Initialize interface data
        interface_data = {
            'interface': interface_name,
            'description': '',
            'mode': '',
            'vlan': '',
            'native_vlan': '',
            'allowed_vlans': ''
        }
        
        # Extract description
        desc_match = re.search(r'description\s+(.+?)(?:\n|$)', block)
        if desc_match:
            interface_data['description'] = desc_match.group(1).strip()
        
        # Extract mode
        if 'switchport mode access' in block:
            interface_data['mode'] = 'access'
        elif 'switchport mode trunk' in block:
            interface_data['mode'] = 'trunk'
        
        # Extract access VLAN
        vlan_match = re.search(r'switchport access vlan\s+(\d+)', block)
        if vlan_match:
            interface_data['vlan'] = vlan_match.group(1)
        
        # Extract native VLAN
        native_vlan_match = re.search(r'switchport trunk native vlan\s+(\d+)', block)
        if native_vlan_match:
            interface_data['native_vlan'] = native_vlan_match.group(1)
        
        # Extract allowed VLANs
        allowed_vlans_match = re.search(r'switchport trunk allowed vlan\s+(.+?)(?:\n|$)', block)
        if allowed_vlans_match:
            interface_data['allowed_vlans'] = allowed_vlans_match.group(1).strip()
        
        interfaces.append(interface_data)
    
    return interfaces

def process_config_files(input_dir, output_file):
    """Process all configuration files in the input directory and create a CSV file."""
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Prepare CSV file
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            'Hostname', 
            'Location', 
            'Interface', 
            'Interface Description', 
            'Mode',
            'VLAN', 
            'Native VLAN',
            'Allowed VLANs'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        # Process each config file
        for config_file in Path(input_dir).glob('*.txt'):
            try:
                # Read config file
                with open(config_file, 'r') as f:
                    config_text = f.read()
                
                # Extract hostname and location
                hostname = extract_hostname(config_text)
                location = extract_location(hostname)
                
                # Parse interface configurations
                interfaces = parse_interface_config(config_text)
                
                # Write to CSV
                for interface in interfaces:
                    writer.writerow({
                        'Hostname': hostname,
                        'Location': location,
                        'Interface': interface['interface'],
                        'Interface Description': interface['description'],
                        'Mode': interface['mode'],
                        'VLAN': interface['vlan'],
                        'Native VLAN': interface['native_vlan'],
                        'Allowed VLANs': interface['allowed_vlans']
                    })
                
                print(f"Processed {config_file.name}")
                
            except Exception as e:
                print(f"Error processing {config_file.name}: {str(e)}")

def main():
    """Main function to run the script."""
    # Define input and output paths
    input_dir = './files/output'
    output_file = './files/report/interface_summary.csv'
    
    # Process the files
    process_config_files(input_dir, output_file)
    print(f"\nCSV file generated: {output_file}")

if __name__ == "__main__":
    main()