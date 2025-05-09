#!/usr/bin/env python3
"""
Cisco Configuration Analysis Pipeline

This script runs the complete pipeline for:
1. Scrubbing sensitive information from Cisco configuration files (optional)
2. Analyzing the configurations for compliance
3. Generating comprehensive PDF reports

Updates:
- Added better error handling
- Improved CLI options
- Added detailed logging for each step
- Added support for custom rule files

Usage:
    python run_enhanced_analysis.py [--input-dir DIR] [--mask-ips] [--mask-hostnames] [--skip-scrubbing]
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path
import logging
from datetime import datetime
import shutil
import glob

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define project directory structure
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
FILES_DIR = PROJECT_ROOT / "files"
OUTPUT_DIR = FILES_DIR / "output"
SCRUBBED_DIR = FILES_DIR / "scrubbed"
REPORT_DIR = FILES_DIR / "report"
REFERENCE_DIR = FILES_DIR / "reference"

# Ensure all directories exist
for directory in [OUTPUT_DIR, SCRUBBED_DIR, REPORT_DIR, REFERENCE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

def copy_rule_file(rules_file, destination_dir=REFERENCE_DIR):
    """
    Copy a rules file to the reference directory with appropriate error handling
    
    Args:
        rules_file: Path to the rules file
        destination_dir: Directory to copy the file to
        
    Returns:
        Path to the copied file or None if error
    """
    try:
        if not os.path.isfile(rules_file):
            logger.error(f"Rules file {rules_file} not found")
            return None
        
        # Create destination directory if it doesn't exist
        os.makedirs(destination_dir, exist_ok=True)
        
        # Determine destination filename
        dest_file = os.path.join(destination_dir, os.path.basename(rules_file))
        
        # Copy the file
        shutil.copy2(rules_file, dest_file)
        logger.info(f"Copied rules file {rules_file} to {dest_file}")
        
        return dest_file
    except Exception as e:
        logger.error(f"Error copying rules file: {e}")
        return None

def list_available_rules():
    """
    List all available rule files in the reference directory
    """
    rule_files = glob.glob(os.path.join(REFERENCE_DIR, "*.json"))
    
    if not rule_files:
        logger.info("No rule files found in reference directory")
        return
    
    logger.info("Available rule files:")
    for rule_file in rule_files:
        logger.info(f"  - {os.path.basename(rule_file)}")

def main():
    parser = argparse.ArgumentParser(description='Run enhanced Cisco configuration analysis pipeline')
    parser.add_argument('--input-dir', default=str(OUTPUT_DIR),
                        help=f'Directory containing input configuration files (default: {OUTPUT_DIR})')
    parser.add_argument('--reference-dir', default=str(REFERENCE_DIR),
                        help=f'Directory containing reference materials (default: {REFERENCE_DIR})')
    parser.add_argument('--mask-ips', action='store_true', help='Mask IP addresses during scrubbing')
    parser.add_argument('--mask-hostnames', action='store_true', help='Mask hostnames during scrubbing')
    parser.add_argument('--rules-file', help='Specific rules file to use for compliance checking')
    parser.add_argument('--list-rules', action='store_true', help='List available rule files')
    parser.add_argument('--skip-scrubbing', action='store_true', 
                        help='Skip scrubbing step and analyze original configurations directly')
    parser.add_argument('--non-interactive', action='store_true',
                        help='Run in non-interactive mode (no prompts)')
    parser.add_argument('--output-dir', default=str(REPORT_DIR),
                        help=f'Directory to save reports (default: {REPORT_DIR})')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # List available rules if requested
    if args.list_rules:
        list_available_rules()
        sys.exit(0)
    
    # Install required rules file if provided
    if args.rules_file:
        rules_dest = copy_rule_file(args.rules_file, args.reference_dir)
        if not rules_dest:
            logger.error(f"Failed to install rules file {args.rules_file}")
            sys.exit(1)
    
    try:
        # Determine which files to analyze
        config_dir = args.input_dir
        
        # Step 1: Run the scrubber (unless skipped)
        if not args.skip_scrubbing:
            logger.info("Step 1: Scrubbing sensitive information from configuration files...")
            
            scrubber_script = SRC_DIR / "cisco_config_scrubber.py"
            scrub_cmd = [
                sys.executable,
                str(scrubber_script),
                "--input-dir", args.input_dir,
                "--output-dir", str(SCRUBBED_DIR)
            ]
            
            if args.mask_ips:
                scrub_cmd.append("--mask-ips")
            
            if args.mask_hostnames:
                scrub_cmd.append("--mask-hostnames")
            
            if args.non_interactive:
                scrub_cmd.append("--non-interactive")
            
            logger.debug(f"Running scrubber command: {' '.join(scrub_cmd)}")
            result = subprocess.run(scrub_cmd, check=True, capture_output=True, text=True)
            logger.info(result.stdout)
            
            if result.stderr:
                logger.warning(result.stderr)
            
            # Set config_dir to scrubbed files for analysis
            config_dir = str(SCRUBBED_DIR)
        else:
            logger.info("Skipping scrubbing step as requested. Analyzing original configurations...")
        
        # Step 2: Run the enhanced analyzer
        logger.info("Step 2: Analyzing configurations for compliance...")
        
        analyzer_script = SRC_DIR / "enhanced_simple_analyzer.py"
        analyze_cmd = [
            sys.executable,
            str(analyzer_script),
            "--config-dir", config_dir,
            "--rules-dir", args.reference_dir,
            "--report-dir", args.output_dir
        ]
        
        if args.skip_scrubbing:
            analyze_cmd.append("--skip-scrubbing")
        
        if args.verbose:
            analyze_cmd.append("--verbose")
        
        logger.debug(f"Running analyzer command: {' '.join(analyze_cmd)}")
        result = subprocess.run(analyze_cmd, check=True, capture_output=True, text=True)
        logger.info(result.stdout)
        
        if result.stderr:
            logger.warning(result.stderr)
        
        # Optional Step 3: Run the debug script for additional interface analysis
        debug_script = SRC_DIR / "debug_enhanced_analyzer.py"
        if os.path.exists(debug_script):
            logger.info("Step 3: Running additional interface analysis...")
            
            debug_cmd = [
                sys.executable,
                str(debug_script)
            ]
            
            try:
                logger.debug(f"Running debug command: {' '.join(debug_cmd)}")
                result = subprocess.run(debug_cmd, check=True, capture_output=True, text=True)
                logger.info(result.stdout)
                
                if result.stderr:
                    logger.warning(result.stderr)
                
                logger.info("Interface analysis complete!")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Interface analysis failed (non-critical): {e}")
        
        logger.info(f"Analysis complete! Reports saved to: {args.output_dir}")
        
        # Print a summary of reports generated
        report_files = glob.glob(os.path.join(args.output_dir, "*_compliance_report.pdf"))
        if report_files:
            logger.info(f"Generated {len(report_files)} compliance reports:")
            for report in report_files:
                logger.info(f"  - {os.path.basename(report)}")
        
        # Step 4: Generate consolidated summary report
        logger.info("Step 4: Generating consolidated summary report...")
        
        summary_script = SRC_DIR / "simplified_report.py"
        if os.path.exists(summary_script):
            summary_cmd = [
                sys.executable,
                str(summary_script),
                "--report-dir", args.output_dir
                # No output-file parameter, let it use the default in the report directory
            ]
            
            try:
                logger.debug(f"Running summary command: {' '.join(summary_cmd)}")
                result = subprocess.run(summary_cmd, check=True, capture_output=True, text=True)
                logger.info(result.stdout)
                
                if result.stderr:
                    logger.warning(result.stderr)
                
                logger.info("Consolidated summary report generation complete!")
                logger.info(f"Consolidated report saved to: {args.output_dir}/consolidated_summary_report.pdf")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Consolidated summary report generation failed (non-critical): {e}")
        else:
            logger.warning(f"Consolidated summary script not found at {summary_script}")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running subprocess: {e}")
        if e.stdout:
            logger.error(f"Process stdout: {e.stdout}")
        if e.stderr:
            logger.error(f"Process stderr: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
