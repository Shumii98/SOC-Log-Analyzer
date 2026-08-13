import re
from datetime import datetime

BRUTE_FORCE_THRESHOLD = 3

print("SOC Log Analyzer")
print("================")
log_file = "logs/security.log"

with open(log_file, "r") as file:
    logs = file.readlines()

print("\nTotal log entries:", len(logs))
failed_logins = 0

for log in logs:
    if "FAILED Login" in log:
        failed_logins += 1

print("Failed login attempts:", failed_logins)

successful_logins = 0

for log in logs:
    if "SUCCESS Login" in log:
        successful_logins += 1

print("Successful login attempts:", successful_logins)

failed_users = {}

for log in logs:
    if "FAILED Login" in log:
        user_match = re.search(r"user=(\S+)", log)

        if user_match:
            user = user_match.group(1)

            if user in failed_users:
                failed_users[user] += 1
            else:
                failed_users[user] = 1

failed_ips = {}

for log in logs:
    if "FAILED Login" in log:
        ip_match = re.search(r"IP=(\d+\.\d+\.\d+\.\d+)", log)

        if ip_match:
            ip = ip_match.group(1)

            if ip in failed_ips:
                failed_ips[ip] += 1
            else:
                failed_ips[ip] = 1

print("\nFailed login attempts by IP:")

for ip, count in failed_ips.items():
    print(f"{ip}: {count}")
suspicious_ips = []

print("\nPotential Brute-Force Attacks:")

for ip, count in failed_ips.items():
    if count >= BRUTE_FORCE_THRESHOLD:
        suspicious_ips.append(ip)
        print(f"ALERT: {ip} - {count} failed login attempts")

print("\nSuspicious IP count:", len(suspicious_ips))

print("\nFailed login attempts by user:")

for user, count in failed_users.items():
    print(f"{user}: {count}")

severity = "LOW"

for ip, count in failed_ips.items():
    if count >= BRUTE_FORCE_THRESHOLD:
        severity = "HIGH"
        break
    elif count >= 2:
        severity = "MEDIUM"

print("\nSecurity Severity:", severity)

recommendations = []

if suspicious_ips:
    recommendations.append(
        "Investigate suspicious IP addresses and consider blocking malicious sources."
    )

if failed_logins >= 3:
    recommendations.append(
        "Review authentication logs for possible brute-force activity."
    )

if failed_users:
    recommendations.append(
        "Review targeted user accounts and verify whether the activity is legitimate."
    )

if not recommendations:
    recommendations.append(
        "No immediate security action is required."
    )

print("\nSecurity Recommendations:")

for recommendation in recommendations:
    print("-", recommendation)
analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

report_file = "reports/security_report.txt"

with open(report_file, "w") as report:
    report.write("SOC LOG ANALYZER SECURITY REPORT\n")
    report.write("================================\n")
    report.write(f"Analysis Time: {analysis_time}\n\n")

    report.write(f"Total log entries: {len(logs)}\n")
    report.write(f"Failed login attempts: {failed_logins}\n")
    report.write(f"Successful login attempts: {successful_logins}\n")
    report.write(f"Suspicious IP count: {len(suspicious_ips)}\n")
    report.write(f"Security Severity: {severity}\n")

    if severity == "HIGH":
        report.write(
            "Alert Status: CRITICAL - Immediate investigation required\n\n"
        )
    elif severity == "MEDIUM":
        report.write(
            "Alert Status: WARNING - Further investigation recommended\n\n"
        )
    else:
        report.write(
            "Alert Status: NORMAL - No immediate threat detected\n\n"
        )

    report.write("Failed Login Attempts by User:\n")
    report.write("-------------------------------\n")

    for user, count in failed_users.items():
        report.write(f"{user} - {count} failed login attempts\n")

    report.write("\n")

    report.write("Security Recommendations:\n")
    report.write("-------------------------\n")

    for recommendation in recommendations:
        report.write(f"- {recommendation}\n")

    report.write("\n")

    report.write("Suspicious IP Addresses:\n")
    report.write("-------------------------\n")

    if suspicious_ips:
        for ip in suspicious_ips:
            report.write(
                f"{ip} - {failed_ips[ip]} failed login attempts\n"
            )
    else:
        report.write("No suspicious IP addresses detected.\n")

print(f"\nSecurity report saved to: {report_file}")