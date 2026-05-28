import json
import requests
import os
from collections import Counter

def load_events(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def analyze_events(events):
    findings = {
        'total_events': len(events),
        'critical_count': 0,
        'high_count': 0,
        'brute_force_detected': False,
        'privilege_escalation_detected': False,
        'suspicious_process_detected': False,
        'top_source_ips': [],
        'failed_login_count': 0,
        'suspicious_users': [],
        'event_summary': {},
        'raw_critical_events': []
    }

    ip_counter = Counter()
    user_counter = Counter()

    for event in events:
        severity = event.get('severity', 'info')
        event_type = event.get('event_type', 'unknown')

        if severity == 'critical':
            findings['critical_count'] += 1
            findings['raw_critical_events'].append(event)
        if severity == 'high':
            findings['high_count'] += 1

        if event_type == 'ssh_failed_login':
            findings['failed_login_count'] += 1

        if event_type == 'privilege_escalation':
            findings['privilege_escalation_detected'] = True

        if event_type == 'process_execution':
            findings['suspicious_process_detected'] = True

        ip_counter[event.get('source_ip', 'unknown')] += 1
        user_counter[event.get('user', 'unknown')] += 1

        findings['event_summary'][event_type] = \
            findings['event_summary'].get(event_type, 0) + 1

    failed_by_ip = Counter()
    for event in events:
        if event.get('event_type') == 'ssh_failed_login':
            failed_by_ip[event.get('source_ip')] += 1

    for ip, count in failed_by_ip.items():
        if count >= 5:
            findings['brute_force_detected'] = True
            break

    findings['top_source_ips'] = ip_counter.most_common(5)
    findings['suspicious_users'] = [u for u, _ in user_counter.most_common(5)]

    return findings

def get_threat_assessment(findings):
    total = findings['total_events']
    critical = findings['critical_count']
    failed = findings['failed_login_count']
    brute = findings['brute_force_detected']
    priv = findings['privilege_escalation_detected']
    proc = findings['suspicious_process_detected']
    ips = findings['top_source_ips']
    summary = findings['event_summary']

    prompt = (
        "You are writing a short threat assessment for a security log analysis tool. "
        "Write it in plain prose, no markdown, no bold text, no asterisks, no bullet points. "
        "Sound like a real analyst who looked at the data and is explaining what they found. "
        "Be direct and specific. Three short paragraphs max.\n\n"
        "Here is what the tool found across " + str(total) + " security events:\n"
        "Critical events: " + str(critical) + "\n"
        "Failed SSH logins: " + str(failed) + "\n"
        "Brute force detected: " + str(brute) + "\n"
        "Privilege escalation attempts: " + str(priv) + "\n"
        "Suspicious process execution: " + str(proc) + "\n"
        "Top source IPs: " + str(ips) + "\n"
        "Event breakdown: " + str(summary) + "\n\n"
        "First paragraph: what the overall risk level is and why.\n"
        "Second paragraph: what the most concerning findings are and what they suggest.\n"
        "Third paragraph: three specific things that should be done immediately, written as sentences not a list."
    )

    api_key = os.environ.get("GROQ_API_KEY", "")
    url = "https://api.groq.com/openai/v1/chat/completions"

    response = requests.post(
        url,
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json"
        },
        json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 500,
            "temperature": 0.7
        }
    )

    if response.status_code == 200:
        return response.json()['choices'][0]['message']['content']
    else:
        return "API error: " + str(response.status_code) + " - " + response.text

if __name__ == "__main__":
    events = load_events('logs/security_events.json')
    print("Loaded " + str(len(events)) + " events")

    findings = analyze_events(events)
    print("Analysis complete")
    print("Critical events: " + str(findings['critical_count']))
    print("Brute force detected: " + str(findings['brute_force_detected']))
    print("Privilege escalation detected: " + str(findings['privilege_escalation_detected']))

    print("\nGenerating AI threat assessment...")
    assessment = get_threat_assessment(findings)
    print("\n--- THREAT ASSESSMENT ---")
    print(assessment)

    findings['threat_assessment'] = assessment

    with open('logs/analysis_results.json', 'w') as f:
        json.dump(findings, f, indent=2, default=str)

    print("\nResults saved to logs/analysis_results.json")
