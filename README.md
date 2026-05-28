# AI-Driven Security Log Analysis and Threat Intelligence Engine

Python | Groq LLaMA API | Jinja2 | JSON | HTML Reporting

---

## Overview

This project started from a question I kept coming back to in my security coursework
at the University of Tennessee. Log analysis is something every SOC analyst does
manually every day — reading through failed logins, flagging suspicious IPs, looking
for patterns that suggest something is wrong. I wanted to build something that
automates that initial triage and turns raw log data into a readable threat assessment
a human can actually act on.

The tool ingests security event logs, runs behavioral analysis to detect indicators
like brute force patterns, privilege escalation attempts, and suspicious process
execution, then sends the findings to an AI model that generates a plain language
threat assessment. The output is a structured HTML report that reads like something
a junior analyst would produce after reviewing the logs.

---

## What It Does

Ingests security event logs in JSON format covering SSH authentication events,
sudo usage, process execution, and privilege escalation attempts. Analyzes behavioral
patterns to detect brute force activity by flagging source IPs with repeated failed
logins, identifies privilege escalation and suspicious process execution, and
classifies source IPs as internal or external. Sends structured findings to the
Groq LLaMA API to generate a plain language threat assessment with risk level,
key findings, and prioritized remediation steps. Produces a clean HTML threat
intelligence report with severity scoring, event breakdowns, and IP classification.

---

## Sample Output

The tool detected the following across 72 security events:

| Metric | Value |
|---|---|
| Total events analyzed | 72 |
| Critical severity events | 24 |
| Failed login attempts | 42 |
| Brute force detected | Yes |
| Privilege escalation detected | Yes |
| Suspicious process execution detected | Yes |
| Overall risk level | High |

Top suspicious source IPs: 45.33.32.156, 89.248.165.64, 198.20.69.74

The full HTML threat report is available in reports/threat_report.html

---

## Project Structure
---

## How to Run

```bash
git clone https://github.com/Damonlee005/Security-Log-Analysis-Threat-Intelligence-Engine
cd Security-Log-Analysis-Threat-Intelligence-Engine
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export GROQ_API_KEY="your-key-here"
python scripts/log_generator.py
python scripts/analyzer.py
python scripts/report_generator.py
open reports/threat_report.html
```

---

## Dataset

The security event dataset is synthetically generated to simulate realistic Linux
server log activity including normal SSH authentication, brute force attack patterns,
privilege escalation attempts, and suspicious process execution. The generator
produces labeled events with severity scoring across five categories. This approach
is standard practice in security tool development and allows for controlled testing
across known attack scenarios without requiring access to production systems.

---

## AI Integration

The tool uses the Groq API with the LLaMA 3.3 70B model to generate threat
assessments from structured log findings. The prompt is engineered to produce
plain language output that reads like analyst written prose rather than a
templated response, with a focus on what the findings actually mean and what
should be done about them.

---

## Threat Report Preview

Open reports/threat_report.html in your browser to view the full rendered report
with risk scoring, detection summary, event breakdown, IP classification table,
and the AI generated threat assessment.
