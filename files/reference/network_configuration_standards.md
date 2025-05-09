# Network Configuration Standards

## Configuration Requirements

### Authentication and Access Control
- AAA must be enabled

```aaa new-model``` global command must be present

### Password Encryption

- service password-encryption must be enabled

```service password-encryption``` global command must be present

### Management Configuration

- NTP must be configured

```ntp server``` must be present

- An ACL must be attached to every VTY line

```

line vty 0 N ! Where N is any number
  access-class <ACL-NAME> in <vrf-also> ! must be present Any ACL name will do.  vrf-also is optional

```

- SSH version 2 must be used exclusively (no telnet or SSH v1)

```ip ssh version 2``` global command must be present

### Global Defaults

- ```spanning-tree portfast bpduguard default``` command must be present

### Interface Configuration

#### Type 1 - Access

- Any interface with ```switchport mode access``` configured qualifies
- Must include the following commands
  - ```description <any value>```
  - ```switchport access vlan <any value>```
  - ```spanning-tree portfast```

#### Type 2 - Trunk

- Any interface with ```switchport mode trunk``` configured qualifies
- Must include the following commands
  - ```description <any value>```
  - ```switchport trunk allowed vlan <any value```

#### Type 3 - Unshut Unused
- Any interface where the configuration has either
  - no configuration applied to it, or
  - only a ```description <any value>``` applied to it, and
  - is missing the ```shutdown``` command
