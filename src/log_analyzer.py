import re
from datetime import datetime

BRUTE_FORCE_THRESHOLD = 3

LOG_FILE = "logs/security.log"
REPORT_FILE = "reports/security_report.txt"

print("SOC Log Analyzer")
print("================")


# --------------------------------------------------
# 1. Parse security log entries
# --------------------------------------------------

def parse_log_entry(log):
    pattern = (
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} "
        r"\d{2}:\d{2}:\d{2}) "
        r"(?P<status>SUCCESS|FAILED) Login "
        r"user=(?P<user>\S+) "
        r"IP=(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    match = re.search(pattern, log)

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "status": match.group("status"),
        "user": match.group("user"),
        "ip": match.group("ip")
    }


# --------------------------------------------------
# 2. Load and parse logs
# --------------------------------------------------

with open(LOG_FILE, "r") as file:
    raw_logs = file.readlines()

events = []

for log in raw_logs:
    event = parse_log_entry(log)

    if event:
        events.append(event)


print("\nTotal log entries:", len(raw_logs))
print("Successfully parsed events:", len(events))


# --------------------------------------------------
# 3. Analyze authentication activity
# --------------------------------------------------

failed_logins = [
    event for event in events
    if event["status"] == "FAILED"
]

successful_logins = [
    event for event in events
    if event["status"] == "SUCCESS"
]

print("Failed login attempts:", len(failed_logins))
print("Successful login attempts:", len(successful_logins))


# --------------------------------------------------
# 4. Aggregate failed logins by IP and username
# --------------------------------------------------

failed_ips = {}
failed_users = {}

for event in failed_logins:

    ip = event["ip"]
    user = event["user"]

    failed_ips[ip] = failed_ips.get(ip, 0) + 1
    failed_users[user] = failed_users.get(user, 0) + 1


print("\nFailed login attempts by IP:")

for ip, count in failed_ips.items():
    print(f"{ip}: {count}")


print("\nFailed login attempts by user:")

for user, count in failed_users.items():
    print(f"{user}: {count}")


# --------------------------------------------------
# 5. Detect potential brute-force attacks
# --------------------------------------------------

suspicious_ips = []

for ip, count in failed_ips.items():

    if count >= BRUTE_FORCE_THRESHOLD:
        suspicious_ips.append(ip)


# --------------------------------------------------
# 6. Generate security alerts with evidence
# --------------------------------------------------

alerts = []

for event in failed_logins:

    ip = event["ip"]

    if ip in suspicious_ips:

        alerts.append({
            "timestamp": event["timestamp"],
            "ip": event["ip"],
            "user": event["user"],
            "failed_attempts": failed_ips[ip],
            "severity": "HIGH",
            "rule": "BRUTE_FORCE_DETECTION"
        })


print("\nSecurity Alerts:")

if alerts:

    for alert in alerts:
        print(
            f"ALERT | {alert['severity']} | "
            f"{alert['timestamp']} | "
            f"IP={alert['ip']} | "
            f"User={alert['user']} | "
            f"Attempts={alert['failed_attempts']} | "
            f"Rule={alert['rule']}"
        )

else:
    print("No security alerts detected.")


# --------------------------------------------------
# 7. Determine overall security severity
# --------------------------------------------------

severity = "LOW"

if suspicious_ips:
    severity = "HIGH"

elif len(failed_logins) >= 2:
    severity = "MEDIUM"


print("\nSuspicious IP count:", len(suspicious_ips))
print("Security Severity:", severity)


# --------------------------------------------------
# 8. Generate recommendations
# --------------------------------------------------

recommendations = []

if suspicious_ips:

    recommendations.append(
        "Investigate suspicious IP addresses for potential brute-force activity."
    )

    recommendations.append(
        "Review authentication events associated with the affected accounts."
    )

    recommendations.append(
        "Consider temporarily blocking or rate-limiting suspicious sources."
    )

if failed_users:

    recommendations.append(
        "Review targeted user accounts for unauthorized access attempts."
    )

if not recommendations:

    recommendations.append(
        "No immediate security action is required."
    )


print("\nSecurity Recommendations:")

for recommendation in recommendations:
    print("-", recommendation)


# --------------------------------------------------
# 9. Generate professional security report
# --------------------------------------------------

analysis_time = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)

with open(REPORT_FILE, "w") as report:

    report.write("SOC LOG ANALYZER SECURITY REPORT\n")
    report.write("================================\n\n")

    report.write(f"Analysis Time: {analysis_time}\n\n")

    report.write("SUMMARY\n")
    report.write("-------\n")

    report.write(f"Total Log Entries: {len(raw_logs)}\n")
    report.write(f"Parsed Events: {len(events)}\n")
    report.write(f"Failed Login Attempts: {len(failed_logins)}\n")
    report.write(f"Successful Login Attempts: {len(successful_logins)}\n")
    report.write(f"Suspicious IP Count: {len(suspicious_ips)}\n")
    report.write(f"Security Severity: {severity}\n\n")


    # Security alerts

    report.write("SECURITY ALERTS\n")
    report.write("---------------\n")

    if alerts:

        for alert in alerts:

            report.write(
                f"Timestamp: {alert['timestamp']}\n"
            )

            report.write(
                f"Source IP: {alert['ip']}\n"
            )

            report.write(
                f"Target User: {alert['user']}\n"
            )

            report.write(
                f"Failed Attempts: {alert['failed_attempts']}\n"
            )

            report.write(
                f"Severity: {alert['severity']}\n"
            )

            report.write(
                f"Detection Rule: {alert['rule']}\n"
            )

            report.write("\n")

    else:

        report.write(
            "No security alerts detected.\n\n"
        )


    # Failed users

    report.write("FAILED LOGIN ATTEMPTS BY USER\n")
    report.write("-----------------------------\n")

    for user, count in failed_users.items():

        report.write(
            f"{user} - {count} failed login attempts\n"
        )

    report.write("\n")


    # Suspicious IPs

    report.write("SUSPICIOUS IP ADDRESSES\n")
    report.write("-----------------------\n")

    if suspicious_ips:

        for ip in suspicious_ips:

            report.write(
                f"{ip} - "
                f"{failed_ips[ip]} failed login attempts\n"
            )

    else:

        report.write(
            "No suspicious IP addresses detected.\n"
        )

    report.write("\n")


    # Recommendations

    report.write("SECURITY RECOMMENDATIONS\n")
    report.write("------------------------\n")

    for recommendation in recommendations:

        report.write(
            f"- {recommendation}\n"
        )


print(
    f"\nSecurity report saved to: {REPORT_FILE}"
)
