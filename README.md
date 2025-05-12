# NetPy - Network Configuration Compliance Analysis Tool

NetPy is a powerful network configuration compliance analysis tool that helps network engineers validate device configurations against security and best practice standards. It provides detailed analysis, remediation suggestions, and comprehensive reporting capabilities.

## Features

- **Configuration Analysis**: Analyzes network device configurations against predefined compliance rules
- **Command Execution**: Execute commands on network devices and collect output
- **Configuration Deployment**: Send configuration changes to network devices
- **Rule Set Based**: Organizes compliance checks into logical rule sets (Security, Management, Interface, etc.)
- **Detailed Reporting**: Generates comprehensive PDF reports with:
  - Overall compliance scores
  - Rule set specific results
  - Detailed compliance findings
  - Remediation suggestions
  - Configuration appendix
- **Consolidated Reporting**: Ability to generate summary reports across multiple devices
- **Remediation Support**: Provides specific configuration commands to address non-compliant items
- **SharePoint Integration**: Upload output files to SharePoint for team collaboration
- **Docker Support**: Containerized deployment option

## Docker Environment Setup

The project includes a Dockerfile for containerized execution. This ensures consistent environment setup across different systems.

### Building the Docker Image

```bash
# Build the Docker image
docker build -t netpy .
```

### Running the Container

1. **Basic Run**
```bash
docker run -it netpy
```

2. **With Environment Variables**
```bash
docker run -it \
  -e UN1='your_username' \
  -e PW1='your_password' \
  -e JB1_HOST='jumpbox_host' \
  -e JB1_USER='jumpbox_user' \
  -e JB1_PASS='jumpbox_password' \
  netpy
```

3. **With Volume Mounting**
```bash
# Mount the local files directory to persist data
docker run -it \
  -v $(pwd)/files:/app/files \
  netpy
```

4. **Complete Example with All Options**
```bash
docker run -it \
  -v $(pwd)/files:/app/files \
  -e UN1='your_username' \
  -e PW1='your_password' \
  -e UN2='your_username2' \
  -e PW2='your_password2' \
  -e UN3='your_username3' \
  -e PW3='your_password3' \
  -e UN4='your_username4' \
  -e PW4='your_password4' \
  -e JB1_TYPE='cisco_ios' \
  -e JB1_HOST='jumpbox_host' \
  -e JB1_USER='jumpbox_user' \
  -e JB1_PASS='jumpbox_password' \
  -e JB1_SECRET='enable_secret' \
  -e JB1_PORT='22' \
  netpy
```

## Inventory Management

### CSV File Format

Create a CSV file with the following columns:

| Column | Description | Required |
|--------|-------------|----------|
| name | Device name | Yes |
| hostname | Device IP/hostname | Yes |
| platform | Device platform (cisco_ios, cisco_xe, etc.) | Yes |
| port | SSH port | Yes |
| username | Username (or UN1-UN4 for credential variables) | Yes |
| password | Password (or PW1-PW4 for credential variables) | Yes |
| site | Site identifier | Yes |
| function | Device function | Yes |
| commands | Path to commands file | Yes |
| jumpbox | Jump box identifier (optional) | No |

Example CSV:
```csv
name,hostname,platform,port,username,password,site,function,commands,jumpbox
router1,192.168.1.1,cisco_ios,22,UN1,PW1,site1,core,commands/router1.txt,JB1
switch1,192.168.1.2,cisco_ios,22,UN2,PW2,site1,access,commands/switch1.txt,
```

### Creating Inventory

1. Place your CSV file in the `/app/files/` directory
2. Run the inventory creation script:
```bash
python src/createinventory.py
```
3. Select your CSV file from the list when prompted
4. The script will create a `nornir_inventory.yaml` file in `/app/files/`

## Command Execution

The `getoutput.py` script provides functionality to execute commands on network devices and collect their output.

### Basic Usage

1. **Execute Commands**
```bash
python src/getoutput.py
```

2. **Filter by Site or Function**
```bash
python src/getoutput.py --site <site_name>
python src/getoutput.py --function <function_name>
```

3. **Using Jump Box**
```bash
python src/getoutput.py --jumpbox JB1
```

4. **Update Inventory**
```bash
python src/getoutput.py --update inv
```

### Output Files

- Command outputs are saved in `/app/files/output/`
- Each file is named with the pattern: `<hostname>-<timestamp>.txt`
- Outputs include:
  - Command executed
  - Full command output
  - Timestamp and device information

### SharePoint Upload

After command execution, you can upload the output files to SharePoint:

1. Run the script with command execution
2. When prompted "Would you like to upload the output files to sharepoint (y/n)", enter 'y'
3. Enter the customer folder name when prompted
4. Choose whether to remove local files after upload

## Configuration Deployment

The `sendconfig.py` script allows you to send configuration changes to network devices.

### Usage

1. **Basic Configuration Deployment**
```bash
python src/sendconfig.py
```

2. **Filter by Site or Function**
```bash
python src/sendconfig.py --site <site_name>
python src/sendconfig.py --function <function_name>
```

3. **Using Jump Box**
```bash
python src/sendconfig.py --jumpbox JB1
```

### Configuration Files

1. Create configuration files for each device in `/app/files/config/`
2. Reference these files in your inventory CSV under the `commands` column
3. The script will execute these configurations in order

## Compliance Analysis

The `run_enhanced_analysis.py` script performs compliance analysis on network devices.

### Usage

1. **Basic Analysis**
```bash
python src/run_enhanced_analysis.py --config-file files/config/device_config.txt
```

2. **Generate Reports**
```bash
python src/run_enhanced_analysis.py --config-file files/config/device_config.txt --generate-report
```

3. **Consolidated Reporting**
```bash
python src/simplified_report.py --report-dir files/report
```

### Report Format

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

## Network Device Command Execution

The `getoutput.py` script provides functionality to execute commands on network devices and collect their output. This is useful for gathering configuration information, running diagnostics, or performing compliance checks.

### Prerequisites

- Network devices accessible via SSH
- Nornir inventory file (`config.yaml`)
- Command files for each device type (stored in `/app/files/`)

### Usage

1. **Basic Command Execution**

```bash
python src/getoutput.py
```

2. **Filter by Site or Function**

```bash
python src/getoutput.py --site <site_name>
python src/getoutput.py --function <function_name>
```

3. **Using Jump Box**

```bash
python src/getoutput.py --jumpbox JB1
```

4. **Update Inventory**

```bash
python src/getoutput.py --update inv
```

### Configuration

1. **Environment Variables**

The script uses several environment variables for authentication:

- `UN1`, `UN2`, `UN3`, `UN4`: Username variables
- `PW1`, `PW2`, `PW3`, `PW4`: Corresponding password variables
- `JB1_HOST`: Jump box hostname
- `JB1_USER`: Jump box username
- `JB1_PASS`: Jump box password
- `JB1_PORT`: Jump box port (default: 22)
- `JB1_SECRET`: Jump box enable secret (for Cisco devices)

2. **Command Files**

Create command files for each device type in the `/app/files/` directory. The filename should be specified in the device's inventory data under the `commands` attribute.

### Output

- Command outputs are saved in `/app/files/output/`
- Each file is named with the pattern: `<hostname>-<timestamp>.txt`
- Outputs include:
  - Command executed
  - Full command output
  - Timestamp and device information

### Supported Platforms

- Cisco IOS
- Cisco XE
- Cisco NXOS
- Palo Alto PANOS
- Linux/Unix devices

### Jump Box Support

The script supports two types of jump box connections:

1. **Linux/Unix Jump Box**
   - Direct SSH tunneling
   - Uses Paramiko for connection management

2. **Cisco Jump Box**
   - Supports IOS, XE, and NXOS
   - Handles enable mode and command execution
   - Manages session timeouts and command output collection

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