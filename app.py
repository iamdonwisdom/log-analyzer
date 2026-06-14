from flask import Flask, render_template
from collections import Counter
import re

app = Flask(__name__)

def analyze_logs():
    logfile = "sample.log"

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

    ip_counts = Counter(failed_logins)

    suspicious_ips = []
    for ip, count in ip_counts.items():
        if count >= 3:
            suspicious_ips.append((ip, count))

    return {
        "failed_count": len(failed_logins),
        "top_ips": Counter(all_ips).most_common(5),
        "suspicious": suspicious_ips
    }

@app.route("/")
def dashboard():
    data = analyze_logs()
    return render_template("index.html", data=data)

if __name__ == "__main__":
    app.run(debug=True)
