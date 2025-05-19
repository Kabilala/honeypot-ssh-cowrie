#!/usr/bin/env python3

import json
import argparse
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Analyze Cowrie honeypot logs')
    parser.add_argument('-f', '--file', help='Log file to analyze', default='var/log/cowrie/cowrie.json')
    parser.add_argument('-o', '--output', help='Output file for the report', default='honeypot_report.txt')
    parser.add_argument('--ip-details', action='store_true', help='Show detailed per-IP statistics')
    parser.add_argument('--top', type=int, default=10, help='Number of top items to show in each category')
    return parser.parse_args()

def process_logs(logfile):
    """Process the Cowrie JSON log file and extract statistics."""
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
            'sessions': set(),
            'first_seen': None,
            'last_seen': None,
        }),
        'downloaded_files': Counter(),
        'sessions': defaultdict(dict),
        'attacks_over_time': defaultdict(int),
        'command_sequences': defaultdict(list),
        'session_durations': [],
    }
    
    with open(logfile, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                event_id = log_entry.get('eventid', '')
                timestamp = log_entry.get('timestamp', '')
                src_ip = log_entry.get('src_ip', 'unknown')
                session = log_entry.get('session', 'unknown')
                
                # Process timestamp
                dt = None
                if timestamp:
                    try:
                        dt = datetime.strptime(timestamp.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                        date_key = dt.strftime('%Y-%m-%d')
                        hour_key = dt.strftime('%Y-%m-%d %H:00')
                        stats['attacks_over_time'][date_key] += 1
                        
                        # Update first/last seen for this IP
                        if dt:
                            if (not stats['ip_activity'][src_ip]['first_seen'] or 
                                dt < datetime.strptime(stats['ip_activity'][src_ip]['first_seen'].split('.')[0], 
                                                     '%Y-%m-%dT%H:%M:%S')):
                                stats['ip_activity'][src_ip]['first_seen'] = timestamp
                                
                            if (not stats['ip_activity'][src_ip]['last_seen'] or 
                                dt > datetime.strptime(stats['ip_activity'][src_ip]['last_seen'].split('.')[0], 
                                                     '%Y-%m-%dT%H:%M:%S')):
                                stats['ip_activity'][src_ip]['last_seen'] = timestamp
                    except Exception as e:
                        pass
                
                # Track session
                if session != 'unknown':
                    if session not in stats['sessions']:
                        stats['sessions'][session] = {
                            'ip': src_ip,
                            'start_time': timestamp,
                            'commands': [],
                            'login_success': False,
                            'username': '',
                            'password': '',
                        }
                    
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
                    
                    # Update session info
                    if session in stats['sessions']:
                        stats['sessions'][session]['login_success'] = True
                        stats['sessions'][session]['username'] = username
                        stats['sessions'][session]['password'] = password
                    
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
                        
                        # Store command in session
                        if session in stats['sessions']:
                            stats['sessions'][session]['commands'].append(command)
                            stats['command_sequences'][session].append(command)
                        
                elif event_id == 'cowrie.session.file_download':
                    url = log_entry.get('url', '')
                    if url:
                        stats['downloaded_files'][url] += 1
                
                elif event_id == 'cowrie.session.closed':
                    duration = log_entry.get('duration', 0)
                    if duration > 0:
                        stats['session_durations'].append(duration)
                        
            except json.JSONDecodeError:
                continue
                
    return stats

def generate_report(stats, output_file, show_ip_details=False, top_n=10):
    """Generate a comprehensive report from the collected statistics."""
    with open(output_file, 'w') as f:
        f.write("=== Cowrie Honeypot Analysis Report ===\n\n")
        
        f.write("== General Statistics ==\n")
        f.write(f"Total Connections: {stats['total_connections']}\n")
        f.write(f"Unique IPs: {len(stats['unique_ips'])}\n")
        f.write(f"Login Attempts: {stats['login_attempts']}\n")
        f.write(f"Successful Logins: {stats['successful_logins']}\n")
        f.write(f"Unique Sessions: {len(stats['sessions'])}\n")
        
        if stats['session_durations']:
            avg_duration = sum(stats['session_durations']) / len(stats['session_durations'])
            max_duration = max(stats['session_durations'])
            f.write(f"Average Session Duration: {avg_duration:.2f} seconds\n")
            f.write(f"Longest Session Duration: {max_duration:.2f} seconds\n")
        f.write("\n")
        
        f.write(f"== Top {top_n} Commands ==\n")
        for cmd, count in stats['commands'].most_common(top_n):
            f.write(f"{cmd}: {count}\n")
        f.write("\n")
        
        f.write(f"== Top {top_n} Usernames ==\n")
        for username, count in stats['usernames'].most_common(top_n):
            f.write(f"{username}: {count}\n")
        f.write("\n")
        
        f.write(f"== Top {top_n} Passwords ==\n")
        for password, count in stats['passwords'].most_common(top_n):
            f.write(f"{password}: {count}\n")
        f.write("\n")
        
        f.write(f"== Top {top_n} Username/Password Combinations ==\n")
        for (username, password), count in stats['username_password_pairs'].most_common(top_n):
            f.write(f"{username}:{password} - {count}\n")
        f.write("\n")
        
        f.write(f"== Top {top_n} Downloaded Files/URLs ==\n")
        for url, count in stats['downloaded_files'].most_common(top_n):
            f.write(f"{url}: {count}\n")
        f.write("\n")
        
        f.write("== Attack Distribution by Date ==\n")
        for date, count in sorted(stats['attacks_over_time'].items()):
            f.write(f"{date}: {count}\n")
        f.write("\n")
        
        # Find interesting command sequences
        f.write("== Interesting Command Sequences ==\n")
        download_sessions = []
        for session, commands in stats['command_sequences'].items():
            if any('wget' in cmd or 'curl' in cmd for cmd in commands):
                download_sessions.append((session, commands))
                
        for i, (session, commands) in enumerate(download_sessions[:5]):
            ip = stats['sessions'][session].get('ip', 'unknown')
            username = stats['sessions'][session].get('username', 'unknown')
            f.write(f"\nSession {i+1} (ID: {session}, IP: {ip}, User: {username}):\n")
            for cmd in commands:
                f.write(f"  $ {cmd}\n")
        f.write("\n")
        
        if show_ip_details:
            f.write(f"== Top {top_n} Attacking IPs ==\n")
            top_ips = sorted(stats['ip_activity'].items(), 
                            key=lambda x: x[1]['connections'], 
                            reverse=True)[:top_n]
            
            for ip, ip_stats in top_ips:
                f.write(f"\nIP: {ip}\n")
                f.write(f"  Total Connections: {ip_stats['connections']}\n")
                f.write(f"  Login Attempts: {ip_stats['login_attempts']}\n")
                f.write(f"  Successful Logins: {ip_stats['successful_logins']}\n")
                f.write(f"  Unique Sessions: {len(ip_stats['sessions'])}\n")
                
                if ip_stats['first_seen']:
                    f.write(f"  First Seen: {ip_stats['first_seen']}\n")
                if ip_stats['last_seen']:
                    f.write(f"  Last Seen: {ip_stats['last_seen']}\n")
                
                f.write("  Top Commands:\n")
                for cmd, count in ip_stats['commands'].most_common(5):
                    f.write(f"    {cmd}: {count}\n")
                
                f.write("  Top Username/Password Combinations:\n")
                for (username, password), count in ip_stats['username_password_pairs'].most_common(5):
                    f.write(f"    {username}:{password} - {count}\n")
        
    print(f"Report generated: {output_file}")

def main():
    """Main function to run the log analyzer."""
    args = parse_args()
    print(f"Analyzing log file: {args.file}")
    stats = process_logs(args.file)
    generate_report(stats, args.output, args.ip_details, args.top)
    print(f"Analysis complete. Report saved to {args.output}")

if __name__ == '__main__':
    main()