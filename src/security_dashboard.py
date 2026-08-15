import re
import sys
import os
import matplotlib.pyplot as plt
from collections import Counter

LOG_FILE = (
    sys.argv[1]
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1])
    else "logs/security.log"
)

OUTPUT_DIR = "reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def parse_logs():
    failed_ips = Counter()
    failed_users = Counter()
    successful = 0
    failed = 0

    pattern = re.compile(
        r"^(?P<timestamp>[\d\-]+\s[\d:]+)\s+"
        r"(?P<status>SUCCESS|FAILED)\s+Login\s+"
        r"user=(?P<user>\S+)\s+IP=(?P<ip>\S+)$"
    )

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                match = pattern.match(line.strip())

                if not match:
                    continue

                status = match.group("status")
                user = match.group("user")
                ip = match.group("ip")

                if status == "FAILED":
                    failed += 1
                    failed_ips[ip] += 1
                    failed_users[user] += 1
                else:
                    successful += 1

    except FileNotFoundError:
        print(f"Log file not found: {LOG_FILE}")
        return None

    return failed, successful, failed_ips, failed_users


def create_dashboard():
    data = parse_logs()

    if data is None:
        return

    failed, successful, failed_ips, failed_users = data

    # 1. Authentication Summary
    plt.figure(figsize=(8, 5))
    plt.bar(
        ["Successful Logins", "Failed Logins"],
        [successful, failed]
    )
    plt.title("Authentication Summary")
    plt.ylabel("Number of Attempts")
    plt.tight_layout()
    plt.savefig(
        os.path.join(OUTPUT_DIR, "authentication_summary.png"),
        dpi=150
    )
    plt.close()

    # 2. Failed Attempts by IP
    plt.figure(figsize=(9, 5))
    plt.bar(
        list(failed_ips.keys()),
        list(failed_ips.values())
    )
    plt.title("Failed Login Attempts by IP")
    plt.xlabel("Source IP")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(
        os.path.join(OUTPUT_DIR, "failed_logins_by_ip.png"),
        dpi=150
    )
    plt.close()

    # 3. Failed Attempts by User
    plt.figure(figsize=(9, 5))
    plt.bar(
        list(failed_users.keys()),
        list(failed_users.values())
    )
    plt.title("Failed Login Attempts by User")
    plt.xlabel("User")
    plt.ylabel("Failed Attempts")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(
        os.path.join(OUTPUT_DIR, "failed_logins_by_user.png"),
        dpi=150
    )
    plt.close()

    print("SOC Security Dashboard")
    print("======================")
    print(f"Successful logins: {successful}")
    print(f"Failed logins: {failed}")
    print()
    print("Dashboard charts generated:")
    print("reports/authentication_summary.png")
    print("reports/failed_logins_by_ip.png")
    print("reports/failed_logins_by_user.png")


if __name__ == "__main__":
    create_dashboard()