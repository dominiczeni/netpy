#!/usr/bin/env python3
"""
Debug script to identify and categorize interfaces in Cisco configurations
with special focus on AP trunk interfaces
"""

import os
import sys
import re
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define project directory structure
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FILES_DIR = PROJECT_ROOT / "files"
OUTPUT_DIR = FILES_DIR / "output"
DEBUG_DIR = FILES_DIR / "debug"

# Create debug directory if it doesn't exist
os.makedirs(DEBUG_DIR, exist_ok=True)

def parse_config(config_file):
    """Parse a configuration file and extract interfaces."""
    try:
        with open(config_file, 'r') as f:
            config_text = f.read()
        
        # Extract interface sections
        interfaces = {}
        current_interface = None
        current_content = []
        in_interface = False
        
        for line in config_text.splitlines():
            if line.startswith('interface '):
                # Save previous interface if we were processing one
                if current_interface and in_interface:
                    interfaces[current_interface] = current_content
                
                # Start new interface
                current_interface = line[len('interface '):]
                current_content = [line]
                in_interface = True
            elif in_interface and line.strip() and not line.startswith(' '):
                # End of interface section
                interfaces[current_interface] = current_content
                in_interface = False
                current_interface = None
                current_content = []
            elif in_interface:
                current_content.append(line)
        
        # Save last interface if we were processing one
        if current_interface and in_interface:
            interfaces[current_interface] = current_content
        
        return interfaces
    
    except Exception as e:
        logger.error(f"Error parsing config file: {e}")
        return {}

def analyze_interfaces(config_file):
    """Analyze interfaces and categorize them."""
    interfaces = parse_config(config_file)
    
    # Categories for interfaces
    ap_trunk_interfaces = []
    regular_trunk_interfaces = []
    access_interfaces = []
    other_interfaces = []
    
    for interface_name, config_lines in interfaces.items():
        # Skip VLAN and loopback interfaces
        if interface_name.lower().startswith('vlan') or interface_name.lower().startswith('loopback'):
            continue
        
        # Join the config lines for easier analysis
        config_text = '\n'.join(config_lines)
        
        # Check if it's a trunk interface
        is_trunk = any('switchport mode trunk' in line for line in config_lines)
        
        # Check if it's an access interface
        is_access = any('switchport mode access' in line for line in config_lines)
        
        # Check for AP trunk specific configurations
        has_native_vlan_9 = any('switchport trunk native vlan 9' in line for line in config_lines)
        
        # Check if description contains "-AP"
        has_ap_description = False
        for line in config_lines:
            if line.strip().startswith('description ') and '-AP' in line:
                has_ap_description = True
                break
        
        # Categorize interfaces
        if is_trunk:
            if has_native_vlan_9 and has_ap_description:
                # This is an AP trunk interface
                ap_trunk_interfaces.append((interface_name, config_text))
            else:
                # This is a regular trunk interface
                regular_trunk_interfaces.append((interface_name, config_text))
        elif is_access:
            access_interfaces.append((interface_name, config_text))
        else:
            other_interfaces.append((interface_name, config_text))
    
    return {
        'ap_trunk': ap_trunk_interfaces,
        'regular_trunk': regular_trunk_interfaces,
        'access': access_interfaces,
        'other': other_interfaces
    }

def main():
    """Main function."""
    # Find configuration files
    config_files = []
    for ext in ['.txt', '.cfg', '.conf']:
        config_files.extend([f for f in os.listdir(OUTPUT_DIR) if f.endswith(ext)])
    
    if not config_files:
        logger.error(f"No configuration files found in {OUTPUT_DIR}")
        return
    
    # Process each configuration file
    for filename in config_files:
        config_file = os.path.join(OUTPUT_DIR, filename)
        logger.info(f"Analyzing {filename} for interface categorization")
        
        # Analyze interfaces
        interfaces = analyze_interfaces(config_file)
        
        # Create debug report
        debug_file = os.path.join(DEBUG_DIR, f"{os.path.splitext(filename)[0]}_interfaces_debug.txt")
        with open(debug_file, 'w') as f:
            f.write(f"Interface Analysis for {filename}\n")
            f.write("=" * 80 + "\n\n")
            
            # Report on AP trunk interfaces
            f.write(f"AP TRUNK INTERFACES ({len(interfaces['ap_trunk'])})\n")
            f.write("-" * 80 + "\n")
            for interface, config in interfaces['ap_trunk']:
                f.write(f"Interface: {interface}\n")
                f.write(f"Configuration:\n{config}\n\n")
            
            # Report on regular trunk interfaces
            f.write(f"\nREGULAR TRUNK INTERFACES ({len(interfaces['regular_trunk'])})\n")
            f.write("-" * 80 + "\n")
            for interface, config in interfaces['regular_trunk']:
                f.write(f"Interface: {interface}\n")
                f.write(f"Configuration:\n{config}\n\n")
            
            # Report on access interfaces
            f.write(f"\nACCESS INTERFACES ({len(interfaces['access'])})\n")
            f.write("-" * 80 + "\n")
            for interface, _ in interfaces['access']:
                f.write(f"{interface}\n")
            
            # Report on other interfaces
            f.write(f"\nOTHER INTERFACES ({len(interfaces['other'])})\n")
            f.write("-" * 80 + "\n")
            for interface, _ in interfaces['other']:
                f.write(f"{interface}\n")
        
        logger.info(f"Debug report written to {debug_file}")

if __name__ == "__main__":
    main()
