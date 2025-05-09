# NetPy - Network Configuration Compliance Analysis Tool

NetPy is a powerful network configuration compliance analysis tool that helps network engineers validate device configurations against security and best practice standards. It provides detailed analysis, remediation suggestions, and comprehensive reporting capabilities.

## Features

- **Configuration Analysis**: Analyzes network device configurations against predefined compliance rules
- **Rule Set Based**: Organizes compliance checks into logical rule sets (Security, Management, Interface, etc.)
- **Detailed Reporting**: Generates comprehensive PDF reports with:
  - Overall compliance scores
  - Rule set specific results
  - Detailed compliance findings
  - Remediation suggestions
  - Configuration appendix
- **Consolidated Reporting**: Ability to generate summary reports across multiple devices
- **Remediation Support**: Provides specific configuration commands to address non-compliant items
- **Docker Support**: Containerized deployment option

## Prerequisites

- Python 3.6 or higher
- Network devices accessible via SSH
- Required Python packages (see requirements.txt)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/netpy.git
cd netpy
```

2. Install required packages:
```bash
pip install -r src/requirements.txt
```

3. (Optional) Build and run using Docker:
```bash
docker build -t netpy .
docker run -v $(pwd)/files:/app/files netpy
```

## Project Structure

```

## Usage

### Basic Analysis

Run a compliance analysis on a single device:

```bash
python src/run_enhanced_analysis.py --config-file files/config/device_config.txt
```

### Generate Reports

Generate a detailed PDF report:

```bash
python src/run_enhanced_analysis.py --config-file files/config/device_config.txt --generate-report
```

Generate a consolidated report for multiple devices:

```bash
python src/simplified_report.py --report-dir files/report
```

## Report Format

The generated reports include:

1. **Summary Page**
   - Device information
   - Overall compliance score
   - Rule set summary table

2. **Detailed Results**
   - Per-rule set compliance details
   - Specific findings and recommendations
   - Remediation commands

3. **Configuration Appendix**
   - Full device configuration
   - Line-by-line analysis

## Rule Sets

The tool includes several predefined rule sets:

- **Security**: Authentication, access control, and security features
- **Management**: Management protocols and access methods
- **Interface**: Interface configuration and security
- **Routing**: Routing protocol configuration and security
- **Services**: Network services and protocols

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[Add your license information here]

## Support

For support, please [add your support contact information]