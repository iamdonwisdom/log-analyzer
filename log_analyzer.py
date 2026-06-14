import re
from collections import Counter

logfile = input("Enter log file path: ")

failed_logins = []
all_ips = []

with open(logfile, "r", errors="ignore") as file:
    for line in file:

        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)

        if ip_match:
            ip = ip_match.group()
            all_ips.append(ip)

        if "Failed password" in line and ip_match:
            failed_logins.append(ip)

print("\n===== SECURITY LOG REPORT =====")

print(f"\nFailed Login Attempts: {len(failed_logins)}")

counter = Counter(failed_logins)

print("\nPotential Brute Force IPs:")

for ip, count in counter.items():
    if count >= 5:
        print(f"- {ip} ({count} attempts)")

print("\nTop Source IPs:")

for ip, count in Counter(all_ips).most_common(5):
    print(f"- {ip}: {count} events")

print("\n================================")
