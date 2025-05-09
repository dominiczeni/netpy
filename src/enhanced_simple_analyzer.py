#!/usr/bin/env python3
"""
Enhanced Simple Cisco Configuration Analyzer

This script analyzes Cisco configurations against compliance rules defined in JSON files
and generates detailed PDF reports with color-coded summaries and interface lists.

Updates:
- Added support for unused interface detection rule
- Enhanced rule handling for interface-specific compliance
- Improved reporting for compliance categories
"""

import os
import sys
import re
import json
import glob
import argparse
import logging
from datetime import datetime
from pathlib import Path
from fpdf import FPDF
import textwrap

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define project directory structure
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
FILES_DIR = PROJECT_ROOT / "files"
SCRUBBED_DIR = FILES_DIR / "scrubbed"
REPORT_DIR = FILES_DIR / "report"
REFERENCE_DIR = FILES_DIR / "reference"

def parse_config(config_file):
    """Parse a configuration file into sections."""
    try:
        logger.debug(f"Attempting to parse config file: {config_file}")
        
        if not os.path.exists(config_file):
            logger.error(f"Config file {config_file} does not exist")
            return None
            
        if not os.access(config_file, os.R_OK):
            logger.error(f"Config file {config_file} is not readable")
            return None
            
        with open(config_file, 'r') as f:
            config_text = f.read()
            
        if not config_text.strip():
            logger.error(f"Config file {config_file} is empty")
            return None
            
        logger.debug(f"Successfully read {len(config_text)} bytes from {config_file}")
        
        # Extract interface sections
        interfaces = {}
        current_interface = None
        current_content = []
        in_interface = False
        
        # Process line by line to correctly handle interface sections
        for line in config_text.splitlines():
            if line.startswith('interface '):
                # Save previous interface if we were processing one
                if current_interface and in_interface:
                    interfaces[current_interface] = '\n'.join(current_content)
                
                # Start new interface
                current_interface = line[len('interface '):]
                current_content = [line]
                in_interface = True
            elif in_interface and line.strip() and not line.startswith(' '):
                # End of interface section
                interfaces[current_interface] = '\n'.join(current_content)
                in_interface = False
                current_interface = None
                current_content = []
            elif in_interface:
                current_content.append(line)
        
        # Save last interface if we were processing one
        if current_interface and in_interface:
            interfaces[current_interface] = '\n'.join(current_content)
        
        logger.debug(f"Found {len(interfaces)} interfaces in {config_file}")
        
        # Extract VTY line sections
        vty_lines = {}
        current_vty = None
        current_content = []
        in_vty = False
        
        # Reset and process again for VTY lines
        for line in config_text.splitlines():
            if line.startswith('line vty '):
                # Save previous VTY if we were processing one
                if current_vty and in_vty:
                    vty_lines[current_vty] = '\n'.join(current_content)
                
                # Start new VTY
                current_vty = line[len('line vty '):]
                current_content = [line]
                in_vty = True
            elif in_vty and line.strip() and not line.startswith(' '):
                # End of VTY section
                vty_lines[current_vty] = '\n'.join(current_content)
                in_vty = False
                current_vty = None
                current_content = []
            elif in_vty:
                current_content.append(line)
        
        # Save last VTY if we were processing one
        if current_vty and in_vty:
            vty_lines[current_vty] = '\n'.join(current_content)
        
        # Extract console line sections
        console_lines = {}
        current_console = None
        current_content = []
        in_console = False
        
        # Reset and process again for console lines
        for line in config_text.splitlines():
            if line.startswith('line con '):
                # Save previous console if we were processing one
                if current_console and in_console:
                    console_lines[current_console] = '\n'.join(current_content)
                
                # Start new console
                current_console = line[len('line con '):]
                current_content = [line]
                in_console = True
            elif in_console and line.strip() and not line.startswith(' '):
                # End of console section
                console_lines[current_console] = '\n'.join(current_content)
                in_console = False
                current_console = None
                current_content = []
            elif in_console:
                current_content.append(line)
        
        # Save last console if we were processing one
        if current_console and in_console:
            console_lines[current_console] = '\n'.join(current_content)
        
        # All other sections will be in global config
        result = {
            'config_text': config_text,
            'interfaces': interfaces,
            'vty_lines': vty_lines,
            'console_lines': console_lines
        }
        
        logger.debug(f"Successfully parsed {config_file}")
        return result
        
    except Exception as e:
        logger.error(f"Error parsing config file {config_file}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return None

def load_rules(rules_dir):
    """Load compliance rules from JSON files."""
    try:
        rules = []
        rule_files = glob.glob(os.path.join(rules_dir, "*.json"))
        
        for rule_file in rule_files:
            with open(rule_file, 'r') as f:
                data = json.load(f)
                if "rule_sets" in data:
                    rules.extend(data["rule_sets"])
                    logger.info(f"Loaded {len(data['rule_sets'])} rule sets from {rule_file}")
                else:
                    logger.warning(f"File {rule_file} has invalid rule format (missing 'rule_sets')")
        
        return rules
    except Exception as e:
        logger.error(f"Error loading rules: {e}")
        return []

def check_rule(config_text, rule):
    """Check if a rule is compliant in the given configuration text."""
    try:
        pattern = rule.get('pattern', '')
        match_type = rule.get('match_type', 'regex')
        
        if not pattern:
            return False
            
        if match_type == 'exists':
            return bool(re.search(pattern, config_text, re.MULTILINE))
        elif match_type == 'absent':
            return not bool(re.search(pattern, config_text, re.MULTILINE))
        elif match_type == 'regex':
            return bool(re.search(pattern, config_text, re.MULTILINE))
        else:
            logger.warning(f"Unknown match type: {match_type}")
            return False
            
    except Exception as e:
        logger.error(f"Error checking rule: {str(e)}")
        return False

def check_interface_criteria(interface_config, criteria):
    """Check if an interface meets the specified criteria."""
    try:
        # If criteria is a list, convert it to a dictionary with 'all_of'
        if isinstance(criteria, list):
            criteria = {'all_of': criteria}
        
        # Check 'all_of' conditions
        for condition in criteria.get('all_of', []):
            if not check_rule(interface_config, condition):
                return False
        
        # Check 'none_of' conditions
        for condition in criteria.get('none_of', []):
            if check_rule(interface_config, condition):
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error checking interface criteria: {str(e)}")
        return False

def analyze_config(config_file, rules):
    """Analyze a configuration file against the rules."""
    try:
        # Parse the configuration
        config = parse_config(config_file)
        if not config:
            return None
            
        results = {
            'filename': os.path.basename(config_file),
            'config_file': config_file,
            'compliant_rules': 0,
            'non_compliant_rules': 0,
            'rule_sets': {}  # Changed from 'categories' to 'rule_sets'
        }
        
        # Process each rule set
        for rule_set in rules:
            rule_set_name = rule_set.get('name', 'Unknown')
            if rule_set_name not in results['rule_sets']:
                results['rule_sets'][rule_set_name] = {
                    'description': rule_set.get('description', ''),
                    'compliant': [],
                    'non_compliant': []
                }
            
            # Process global rules
            for rule in rule_set.get('rules', []):
                compliant = check_rule(config['config_text'], rule)
                if compliant:
                    results['rule_sets'][rule_set_name]['compliant'].append(rule)
                    results['compliant_rules'] += 1
                else:
                    results['rule_sets'][rule_set_name]['non_compliant'].append(rule)
                    results['non_compliant_rules'] += 1
            
            # Process section-specific rules
            sections = rule_set.get('sections', {})
            if sections:
                # Check VTY lines
                if 'vty' in sections:
                    for vty_name, vty_config in config.get('vty_lines', {}).items():
                        for rule in rule_set.get('rules', []):
                            compliant = check_rule(vty_config, rule)
                            if compliant:
                                results['rule_sets'][rule_set_name]['compliant'].append(rule)
                                results['compliant_rules'] += 1
                            else:
                                results['rule_sets'][rule_set_name]['non_compliant'].append(rule)
                                results['non_compliant_rules'] += 1
                
                # Check console lines
                if 'console' in sections:
                    for con_name, con_config in config.get('console_lines', {}).items():
                        for rule in rule_set.get('rules', []):
                            compliant = check_rule(con_config, rule)
                            if compliant:
                                results['rule_sets'][rule_set_name]['compliant'].append(rule)
                                results['compliant_rules'] += 1
                            else:
                                results['rule_sets'][rule_set_name]['non_compliant'].append(rule)
                                results['non_compliant_rules'] += 1
            
            # Process interface rules
            for interface_rule in rule_set.get('interface_rules', []):
                for interface, interface_config in config.get('interfaces', {}).items():
                    if check_interface_criteria(interface_config, interface_rule.get('detection_criteria', {})):
                        for rule in interface_rule.get('rules', []):
                            compliant = check_rule(interface_config, rule)
                            if compliant:
                                results['rule_sets'][rule_set_name]['compliant'].append(rule)
                                results['compliant_rules'] += 1
                            else:
                                results['rule_sets'][rule_set_name]['non_compliant'].append(rule)
                                results['non_compliant_rules'] += 1
        
        return results
        
    except Exception as e:
        logger.error(f"Error analyzing configuration: {str(e)}")
        return None

def generate_pdf_report(results, output_file):
    """Generate a PDF report from the analysis results."""
    try:
        pdf = FPDF()
        
        # Section 1: Summary Table
        pdf.add_page()
        
        # Title and Device Name
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Configuration Compliance Report', 0, 1, 'C')
        pdf.ln(5)
        
        # Device Name
        device_name = os.path.basename(results.get('config_file', 'Unknown Device'))
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f'Device: {device_name}', 0, 1, 'C')
        pdf.ln(5)
        
        # Overall Compliance Score Banner
        total_compliant = sum(len(rule_set.get('compliant', [])) for rule_set in results.get('rule_sets', {}).values())
        total_non_compliant = sum(len(rule_set.get('non_compliant', [])) for rule_set in results.get('rule_sets', {}).values())
        total_rules = total_compliant + total_non_compliant
        overall_score = (total_compliant / total_rules * 10) if total_rules > 0 else 0
        compliance_percentage = (total_compliant / total_rules * 100) if total_rules > 0 else 0
        
        # Color code the overall score
        if overall_score >= 8:
            pdf.set_fill_color(150, 255, 150)  # Green
        elif overall_score >= 5:
            pdf.set_fill_color(255, 255, 150)  # Yellow
        else:
            pdf.set_fill_color(255, 150, 150)  # Red
        
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f'Overall Compliance Score: {overall_score:.2f}/10 ({compliance_percentage:.1f}%)', 0, 1, 'C', 1)
        pdf.ln(5)
        
        # Center the table by calculating margins
        table_width = 150  # Total width of the table
        left_margin = (pdf.w - table_width) / 2
        
        # Create a rule set compliance overview table
        pdf.set_fill_color(240, 240, 240)  # Light gray background for header
        pdf.set_font('Arial', 'B', 10)
        pdf.set_x(left_margin)  # Set starting X position for centering
        pdf.cell(60, 10, 'Rule Set', 1, 0, 'L', 1)
        pdf.cell(30, 10, 'Compliant', 1, 0, 'C', 1)
        pdf.cell(30, 10, 'Failed', 1, 0, 'C', 1)
        pdf.cell(30, 10, 'Score', 1, 1, 'C', 1)
        
        # Add a row for each rule set
        pdf.set_font('Arial', '', 9)
        for rule_set_name, rule_set_data in results.get('rule_sets', {}).items():
            compliant = len(rule_set_data.get('compliant', []))
            non_compliant = len(rule_set_data.get('non_compliant', []))
            total = compliant + non_compliant
            score = (compliant / total * 10) if total > 0 else 0
            
            # Rule set name - may need truncation if too long
            display_name = rule_set_name
            if len(display_name) > 30:
                display_name = display_name[:27] + "..."
            
            pdf.set_x(left_margin)  # Reset X position for each row
            pdf.cell(60, 10, display_name, 1, 0)
            
            # Color code the compliant count
            if compliant > 0:
                pdf.set_fill_color(220, 255, 220)  # Light green
                pdf.cell(30, 10, f"{compliant}", 1, 0, 'C', 1)
            else:
                pdf.set_fill_color(255, 255, 255)
                pdf.cell(30, 10, f"{compliant}", 1, 0, 'C')
            
            # Color code the non-compliant count
            if non_compliant > 0:
                pdf.set_fill_color(255, 220, 220)  # Light red
                pdf.cell(30, 10, f"{non_compliant}", 1, 0, 'C', 1)
            else:
                pdf.set_fill_color(255, 255, 255)
                pdf.cell(30, 10, f"{non_compliant}", 1, 0, 'C')
            
            # Color code the score
            if score >= 8:
                pdf.set_fill_color(150, 255, 150)  # Green
            elif score >= 5:
                pdf.set_fill_color(255, 255, 150)  # Yellow
            else:
                pdf.set_fill_color(255, 150, 150)  # Red
                
            pdf.cell(30, 10, f"{score:.2f}", 1, 1, 'C', 1)
        
        # Add totals row
        pdf.set_font('Arial', 'B', 10)
        pdf.set_fill_color(220, 220, 220)  # Darker gray for totals row
        pdf.set_x(left_margin)  # Reset X position for totals row
        pdf.cell(60, 10, 'TOTAL', 1, 0, 'L', 1)
        
        # Color code the total compliant
        if total_compliant > 0:
            pdf.set_fill_color(220, 255, 220)  # Light green
            pdf.cell(30, 10, f"{total_compliant}", 1, 0, 'C', 1)
        else:
            pdf.set_fill_color(220, 220, 220)
            pdf.cell(30, 10, f"{total_compliant}", 1, 0, 'C', 1)
        
        # Color code the total non-compliant
        if total_non_compliant > 0:
            pdf.set_fill_color(255, 220, 220)  # Light red
            pdf.cell(30, 10, f"{total_non_compliant}", 1, 0, 'C', 1)
        else:
            pdf.set_fill_color(220, 220, 220)
            pdf.cell(30, 10, f"{total_non_compliant}", 1, 0, 'C', 1)
        
        # Color code the overall score
        if overall_score >= 8:
            pdf.set_fill_color(150, 255, 150)  # Green
        elif overall_score >= 5:
            pdf.set_fill_color(255, 255, 150)  # Yellow
        else:
            pdf.set_fill_color(255, 150, 150)  # Red
            
        pdf.cell(30, 10, f"{overall_score:.2f}", 1, 1, 'C', 1)

        # Sections 2-N: One section per rule set
        for rule_set_name, data in results.get('rule_sets', {}).items():
            pdf.add_page()
            
            # Rule set header
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, rule_set_name, 0, 1, 'C')
            if 'description' in data:
                pdf.set_font('Arial', 'I', 10)
                pdf.multi_cell(0, 6, data['description'])
            pdf.ln(5)
            
            # Non-compliant rules
            if data.get('non_compliant'):
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(255, 0, 0)  # Red
                pdf.cell(0, 10, 'Failed Rules:', 0, 1)
                pdf.set_text_color(0, 0, 0)  # Reset color
                
                for item in data.get('non_compliant', []):
                    pdf.set_font('Arial', 'B', 10)
                    pdf.cell(0, 8, f"Rule {item.get('id')}: {item.get('name')}", 0, 1)
                    pdf.set_font('Arial', '', 10)
                    pdf.multi_cell(0, 6, f"Description: {item.get('description')}")
                    pdf.multi_cell(0, 6, f"Severity: {item.get('severity')}")
                    
                    # Display remediation if available
                    if 'remediation' in item:
                        pdf.set_font('Arial', 'B', 10)
                        pdf.cell(0, 8, "Remediation:", 0, 1)
                        pdf.set_font('Courier', '', 9)
                        pdf.set_fill_color(240, 240, 240)
                        pdf.rect(pdf.get_x(), pdf.get_y(), 190, 20, 'F')
                        pdf.set_xy(pdf.get_x() + 5, pdf.get_y() + 5)
                        pdf.multi_cell(180, 6, item['remediation'].get('command', ''))
                        pdf.set_font('Arial', 'I', 9)
                        pdf.multi_cell(0, 6, f"Notes: {item['remediation'].get('notes', '')}")
                    pdf.ln(2)
            
            # Compliant rules
            if data.get('compliant'):
                pdf.set_font('Arial', 'B', 12)
                pdf.set_text_color(0, 128, 0)  # Green
                pdf.cell(0, 10, 'Compliant Rules:', 0, 1)
                pdf.set_text_color(0, 0, 0)  # Reset color
                
                for item in data.get('compliant', []):
                    pdf.set_font('Arial', 'B', 10)
                    pdf.cell(0, 8, f"Rule {item.get('id')}: {item.get('name')}", 0, 1)
                    pdf.set_font('Arial', '', 10)
                    pdf.multi_cell(0, 6, f"Description: {item.get('description')}")
                    pdf.ln(2)
        
        # Section N+1: Remediation Configuration
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Remediation Configuration', 0, 1, 'C')
        pdf.ln(5)
        
        # Display remediation commands
        pdf.set_font('Courier', '', 10)
        remediation_commands = generate_remediation_script(results)
        if remediation_commands:
            lines = remediation_commands.split('\n')
            for line in lines:
                # Check if we need a new page
                if pdf.get_y() > 250:
                    pdf.add_page()
                pdf.multi_cell(0, 5, line)
        else:
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 10, "No remediation required", 0, 1)
        
        # Section N+2: Configuration Appendix
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Configuration Appendix', 0, 1, 'C')
        pdf.ln(5)
        
        # Display configuration
        pdf.set_font('Courier', '', 10)
        try:
            with open(results['config_file'], 'r') as f:
                config_text = f.read()
                lines = config_text.split('\n')
                for line in lines:
                    # Check if we need a new page
                    if pdf.get_y() > 250:
                        pdf.add_page()
                    pdf.multi_cell(0, 5, line)
        except Exception as e:
            logger.error(f"Error reading configuration file: {str(e)}")
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 10, "Error reading configuration file", 0, 1)
        
        # Save the PDF
        pdf.output(output_file)
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

def format_interface_list(interfaces):
    """Format a list of interfaces with one interface per line."""
    all_interfaces = sorted(list(interfaces))
    interface_text = ""
    
    for intf in all_interfaces:
        interface_text += f"{intf}\n"
    
    return interface_text

def group_rules_by_id(rules):
    """Group rules by their ID."""
    grouped = {}
    for rule in rules:
        rule_id = rule.get('id', '')
        if rule_id not in grouped:
            grouped[rule_id] = {
                'rule': rule,
                'affected_interfaces': [],
                'affected_sections': []
            }
        
        if 'interface' in rule:
            grouped[rule_id]['affected_interfaces'].append(rule['interface'])
        elif 'section' in rule:
            grouped[rule_id]['affected_sections'].append(rule['section'])
    
    return grouped

def display_rule_details(pdf, details):
    """Display details for a single rule."""
    rule = details['rule']
    affected_interfaces = details['affected_interfaces']
    affected_sections = details['affected_sections']
    
    pdf.set_font('Arial', 'B', 10)
    name = rule.get('name', '')
    
    if 'interface_type' in rule:
        interface_type = rule.get('interface_type', '')
        pdf.cell(0, 7, f"{rule['id']}: {name} ({interface_type} interface)", 0, 1)
    else:
        pdf.cell(0, 7, f"{rule['id']}: {name}", 0, 1)
    
    pdf.set_font('Arial', '', 9)
    description = rule.get('description', '')
    pdf.cell(10, 5, '*', 0, 0)
    pdf.multi_cell(0, 5, f"Description: {description}")
    
    # Display severity if available
    severity = rule.get('severity', '')
    if severity:
        pdf.cell(10, 5, '*', 0, 0)
        pdf.set_text_color(*pdf.severity_color(severity))
        pdf.cell(0, 5, f"Severity: {severity.upper()}", 0, 1)
        pdf.set_text_color(0, 0, 0)  # Reset text color
    
    # Display affected interfaces if any
    if affected_interfaces:
        pdf.cell(10, 5, '*', 0, 0)
        pdf.cell(0, 5, "Affected Interfaces:", 0, 1)
        interface_text = format_interface_list(affected_interfaces)
        pdf.set_x(pdf.get_x() + 10)  # Indent
        pdf.multi_cell(0, 5, interface_text)
    
    # Display affected sections if any
    if affected_sections:
        pdf.cell(10, 5, '*', 0, 0)
        pdf.multi_cell(0, 5, f"Affected Sections: {', '.join(affected_sections)}")
    
    # Display expected configuration
    expected_pattern = rule.get('pattern', '')
    if expected_pattern:
        pdf.cell(10, 5, '*', 0, 0)
        pdf.multi_cell(0, 5, f"Expected Configuration: {expected_pattern}")
    
    pdf.ln(3)

def display_compliant_rules(pdf, compliant):
    """Display summary of compliant rules."""
    # Count unique rule IDs
    compliant_rule_ids = set(rule.get('id', '') for rule in compliant)
    
    pdf.set_font('Arial', 'B', 11)
    pdf.set_fill_color(220, 255, 220)  # Light green
    pdf.cell(0, 10, f"Compliant Rules: {len(compliant_rule_ids)} rule(s)", 0, 1, 'L', 1)
    pdf.set_fill_color(255, 255, 255)
    
    # Group by rule ID
    compliant_grouped = {}
    for rule in compliant:
        rule_id = rule.get('id', '')
        if rule_id not in compliant_grouped:
            compliant_grouped[rule_id] = {
                'rule': rule,
                'count': 1
            }
        else:
            compliant_grouped[rule_id]['count'] += 1
    
    # List compliant rules
    for rule_id, details in compliant_grouped.items():
        rule = details['rule']
        count = details['count']
        
        pdf.set_font('Arial', 'B', 10)
        name = rule.get('name', '')
        
        if 'interface_type' in rule:
            interface_type = rule.get('interface_type', '')
            pdf.cell(0, 7, f"{rule_id}: {name} ({interface_type} interface) - {count} instance(s)", 0, 1)
        else:
            pdf.cell(0, 7, f"{rule_id}: {name}", 0, 1)
        
        pdf.set_font('Arial', '', 9)
        description = rule.get('description', '')
        pdf.cell(10, 5, '*', 0, 0)
        pdf.multi_cell(0, 5, f"Description: {description}")

def display_configuration(pdf, config_file):
    """Display the full configuration with line numbers."""
    try:
        with open(config_file, 'r') as f:
            config_text = f.read()
        
        pdf.set_font('Courier', '', 8)
        lines = config_text.splitlines()
        
        # Process in chunks to avoid memory issues
        chunk_size = 1000
        
        for i in range(0, len(lines), chunk_size):
            chunk = lines[i:i+chunk_size]
            
            for j, line in enumerate(chunk):
                line_num = i + j + 1
                # Format with line numbers
                pdf.cell(20, 5, f"{line_num}:", 0, 0)
                pdf.multi_cell(0, 5, line)
            
            # Check if we need to add a new page for next chunk
            if i + chunk_size < len(lines):
                pdf.add_page()
            
        if len(lines) > chunk_size:
            pdf.set_font('Arial', 'I', 10)
            pdf.cell(0, 10, f"Configuration is {len(lines)} lines long.", 0, 1)
            
    except Exception as e:
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 5, f"Error loading configuration: {str(e)}")

def generate_remediation_commands(rule, interface=None):
    """Generate remediation commands for a non-compliant rule."""
    try:
        # Get remediation from the rule
        remediation = rule.get('remediation', {})
        if not remediation:
            return f"# No remediation command defined for rule: {rule.get('id')}"
            
        command = remediation.get('command', '')
        context = remediation.get('context', 'global')
        notes = remediation.get('notes', '')
        
        # If this is an interface rule, add interface context
        if interface:
            return f"interface {interface}\n {command}\nexit"
        else:
            return command
            
    except Exception as e:
        logger.error(f"Error generating remediation commands: {str(e)}")
        return f"# Error generating remediation command: {str(e)}"

def generate_remediation_script(results):
    """Generate a complete remediation script based on non-compliant rules."""
    try:
        script_lines = []
        script_lines.append("! Remediation Script")
        script_lines.append("! Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        script_lines.append("! Device: " + results.get('filename', 'Unknown'))
        script_lines.append("")
        
        # Group rules by category
        for category, data in results.get('rule_sets', {}).items():
            non_compliant = data.get('non_compliant', [])
            if non_compliant:
                script_lines.append(f"! {category} Remediation")
                script_lines.append("!")
                
                # Group by rule ID to avoid duplicates
                rule_groups = {}
                for rule in non_compliant:
                    rule_id = rule.get('id')
                    if rule_id not in rule_groups:
                        rule_groups[rule_id] = {
                            'rule': rule,
                            'interfaces': set(),
                            'sections': set()
                        }
                    
                    if 'interface' in rule:
                        rule_groups[rule_id]['interfaces'].add(rule['interface'])
                    if 'section' in rule:
                        rule_groups[rule_id]['sections'].add(rule['section'])
                
                # Generate commands for each rule group
                for rule_id, group in rule_groups.items():
                    rule = group['rule']
                    script_lines.append(f"! Rule: {rule_id}")
                    script_lines.append(f"! Description: {rule.get('description', 'No description')}")
                    
                    # Add interface-specific commands
                    if group['interfaces']:
                        for interface in sorted(group['interfaces']):
                            commands = generate_remediation_commands(rule, interface)
                            script_lines.append(commands)
                    
                    # Add section-specific commands
                    if group['sections']:
                        for section in sorted(group['sections']):
                            commands = generate_remediation_commands(rule)
                            script_lines.append(f"! Section: {section}")
                            script_lines.append(commands)
                    
                    # Add global commands if no specific interfaces or sections
                    if not group['interfaces'] and not group['sections']:
                        commands = generate_remediation_commands(rule)
                        script_lines.append(commands)
                    
                    script_lines.append("!")
                
                script_lines.append("")
        
        return "\n".join(script_lines)
        
    except Exception as e:
        logger.error(f"Error generating remediation script: {str(e)}")
        return f"# Error generating remediation script: {str(e)}"

def display_remediation_script(pdf, results):
    """Display the remediation script section in the PDF."""
    pdf.add_page()
    pdf.chapter_title("Configuration Remediation Script")
    
    # Generate remediation commands
    remediation_commands = generate_remediation_script(results)
    
    # Display the commands
    pdf.set_font('Courier', '', 10)
    
    # Add a header
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, "Remediation Script", 0, 1)
    pdf.set_font('Arial', '', 10)
    pdf.multi_cell(0, 5, "The following commands can be used to remediate the non-compliant configurations. " +
                   "Please review and test these commands before applying them to production devices.")
    pdf.ln(5)
    
    # Display the commands
    pdf.set_font('Courier', '', 10)
    for command in remediation_commands:
        if command.startswith('!'):
            # Comments in bold
            pdf.set_font('Courier', 'B', 10)
            pdf.multi_cell(0, 5, command)
            pdf.set_font('Courier', '', 10)
        else:
            pdf.multi_cell(0, 5, command)

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Enhanced Cisco Configuration Analyzer')
    parser.add_argument('--config-dir', default=str(SCRUBBED_DIR), help='Directory with config files')
    parser.add_argument('--rules-dir', default=str(REFERENCE_DIR), help='Directory with rules JSON files')
    parser.add_argument('--report-dir', default=str(REPORT_DIR), help='Directory for PDF reports')
    parser.add_argument('--config-file', help='Single config file to analyze')
    parser.add_argument('--skip-scrubbing', action='store_true', help='If using original files, not scrubbed')
    parser.add_argument('--save-json', action='store_true', help='Save analysis results as JSON files')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()
    
    # Set verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine which directory to use based on skip-scrubbing
    config_dir = args.config_dir
    if args.skip_scrubbing and args.config_dir == str(SCRUBBED_DIR):
        # If using default scrubbed dir but want to skip scrubbing,
        # change to the output dir instead
        config_dir = str(FILES_DIR / "output")
        logger.info(f"Using original files from {config_dir}")
    
    # Load rules
    logger.info(f"Loading rules from {args.rules_dir}")
    rules = load_rules(args.rules_dir)
    if not rules:
        logger.error("No rules loaded. Exiting.")
        sys.exit(1)
    
    # Find configurations to analyze
    if args.config_file:
        config_files = [args.config_file]
    else:
        config_files = []
        for ext in ['.txt', '.cfg', '.conf']:
            config_files.extend(glob.glob(os.path.join(config_dir, f"*{ext}")))
    
    if not config_files:
        logger.error(f"No configuration files found in {config_dir}")
        sys.exit(1)
    
    logger.info(f"Found {len(config_files)} configuration files to analyze")
    
    # Process each configuration
    success_count = 0
    for config_file in config_files:
        try:
            # Analyze the configuration
            logger.info(f"Analyzing {config_file}")
            results = analyze_config(config_file, rules)
            
            if not results:
                logger.error(f"Failed to analyze {config_file}")
                continue
            
            # Generate report
            filename = os.path.basename(config_file)
            base_name = os.path.splitext(filename)[0]
            # Remove _scrubbed suffix if present
            if '_scrubbed' in base_name:
                base_name = base_name.replace('_scrubbed', '')
            report_file = os.path.join(args.report_dir, f"{base_name}_compliance_report.pdf")
            
            logger.info(f"Generating report: {report_file}")
            generate_pdf_report(results, report_file)
            
            # Save results as JSON if requested (or always for consolidated report support)
            json_file = os.path.join(args.report_dir, f"{base_name}_compliance_report.json")
            try:
                import json
                
                # Convert set objects to lists for JSON serialization
                serializable_results = dict(results)
                
                if 'interface_summary' in serializable_results:
                    for interface_type, status in serializable_results['interface_summary'].items():
                        if 'compliant' in status and isinstance(status['compliant'], set):
                            serializable_results['interface_summary'][interface_type]['compliant'] = list(status['compliant'])
                        if 'non_compliant' in status and isinstance(status['non_compliant'], set):
                            serializable_results['interface_summary'][interface_type]['non_compliant'] = list(status['non_compliant'])
                
                with open(json_file, 'w') as f:
                    json.dump(serializable_results, f, indent=2)
                
                logger.info(f"Saved analysis results to {json_file}")
            except Exception as e:
                logger.warning(f"Failed to save results as JSON: {e}")
            
            success_count += 1
            logger.info(f"Successfully analyzed {filename} -> {os.path.basename(report_file)}")
            
        except Exception as e:
            logger.error(f"Error processing {config_file}: {e}")
    
    logger.info(f"Analysis complete! Successfully processed {success_count} out of {len(config_files)} files")
    logger.info(f"Reports saved to: {args.report_dir}")

if __name__ == "__main__":
    main()
