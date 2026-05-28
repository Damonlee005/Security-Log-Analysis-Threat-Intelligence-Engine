import json
import os
from datetime import datetime

def generate_report(analysis_path, output_path):
    with open(analysis_path, 'r') as f:
        data = json.load(f)

    severity_color = 'critical'
    if data['critical_count'] > 10:
        severity_color = '#C62828'
        severity_label = 'CRITICAL'
    elif data['critical_count'] > 0 or data['high_count'] > 0:
        severity_color = '#E65100'
        severity_label = 'HIGH'
    else:
        severity_color = '#2E7D32'
        severity_label = 'LOW'

    event_rows = ''
    for event_type, count in data['event_summary'].items():
        event_rows += f'<tr><td>{event_type.replace("_", " ").title()}</td><td>{count}</td></tr>'

    ip_rows = ''
    for ip, count in data['top_source_ips']:
        flag = 'Suspicious' if not ip.startswith('192.168') else 'Internal'
        color = '#C62828' if flag == 'Suspicious' else '#1565C0'
        ip_rows += f'<tr><td>{ip}</td><td>{count}</td><td style="color:{color};font-weight:bold">{flag}</td></tr>'

    assessment_html = data.get('threat_assessment', 'No assessment generated.').replace('\n', '<br>')

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Threat Intelligence Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #212121; }}
        .header {{ background: #1a1a2e; color: white; padding: 30px; border-radius: 8px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0 0 8px 0; font-size: 24px; }}
        .header p {{ margin: 0; opacity: 0.7; font-size: 13px; }}
        .severity-badge {{ display: inline-block; background: {severity_color}; color: white; padding: 6px 16px; border-radius: 4px; font-weight: bold; font-size: 14px; margin-top: 12px; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
        .card h3 {{ margin: 0 0 4px 0; font-size: 13px; color: #757575; text-transform: uppercase; }}
        .card .value {{ font-size: 32px; font-weight: bold; color: #1a1a2e; }}
        .card .value.red {{ color: #C62828; }}
        .section {{ background: white; padding: 24px; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); margin-bottom: 24px; }}
        .section h2 {{ margin: 0 0 16px 0; font-size: 16px; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #1a1a2e; color: white; padding: 10px 12px; text-align: left; font-size: 13px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #e0e0e0; font-size: 13px; }}
        tr:hover td {{ background: #f5f5f5; }}
        .assessment {{ background: #f8f9fa; padding: 20px; border-left: 4px solid #1565C0; border-radius: 4px; line-height: 1.7; font-size: 14px; }}
        .flag-true {{ color: #C62828; font-weight: bold; }}
        .flag-false {{ color: #2E7D32; font-weight: bold; }}
        .footer {{ text-align: center; color: #9e9e9e; font-size: 12px; margin-top: 24px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Threat Intelligence Report</h1>
        <p>Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')} | AI-Driven Security Log Analysis Engine</p>
        <div class="severity-badge">Risk Level: {severity_label}</div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Total Events Analyzed</h3>
            <div class="value">{data['total_events']}</div>
        </div>
        <div class="card">
            <h3>Critical Events</h3>
            <div class="value red">{data['critical_count']}</div>
        </div>
        <div class="card">
            <h3>Failed Login Attempts</h3>
            <div class="value red">{data['failed_login_count']}</div>
        </div>
    </div>

    <div class="section">
        <h2>Detection Summary</h2>
        <table>
            <tr><th>Indicator</th><th>Status</th></tr>
            <tr><td>Brute Force Attack</td><td class="flag-{'true' if data['brute_force_detected'] else 'false'}">{'DETECTED' if data['brute_force_detected'] else 'NOT DETECTED'}</td></tr>
            <tr><td>Privilege Escalation Attempt</td><td class="flag-{'true' if data['privilege_escalation_detected'] else 'false'}">{'DETECTED' if data['privilege_escalation_detected'] else 'NOT DETECTED'}</td></tr>
            <tr><td>Suspicious Process Execution</td><td class="flag-{'true' if data['suspicious_process_detected'] else 'false'}">{'DETECTED' if data['suspicious_process_detected'] else 'NOT DETECTED'}</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Event Type Breakdown</h2>
        <table>
            <tr><th>Event Type</th><th>Count</th></tr>
            {event_rows}
        </table>
    </div>

    <div class="section">
        <h2>Top Source IPs by Activity</h2>
        <table>
            <tr><th>IP Address</th><th>Event Count</th><th>Classification</th></tr>
            {ip_rows}
        </table>
    </div>

    <div class="section">
        <h2>AI-Generated Threat Assessment</h2>
        <div class="assessment">{assessment_html}</div>
    </div>

    <div class="footer">
        Generated by AI-Driven Security Log Analysis and Threat Intelligence Engine
    </div>
</body>
</html>'''

    os.makedirs('reports', exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html)

    print("Report saved to " + output_path)

if __name__ == "__main__":
    generate_report('logs/analysis_results.json', 'reports/threat_report.html')
