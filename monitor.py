import time
import re
from collections import Counter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logfile = "sample.log"

def risk_level(count):
    if count >= 5:
        return "HIGH 🔴"
    elif count >= 3:
        return "MEDIUM 🟠"
    else:
        return "LOW 🟡"

def analyze():
    failed = []
    ips = []

    with open(logfile, "r", errors="ignore") as f:
        for line in f:
            ip = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            if ip:
                ips.append(ip[0])
            if "Failed password" in line and ip:
                failed.append(ip[0])

    counter = Counter(failed)

    print("\n🛡️ LIVE SECURITY REPORT")
    print("------------------------")

    for ip, count in counter.items():
        if count >= 2:
            print(f"[ALERT] {ip} → {count} attempts → {risk_level(count)}")


class Handler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith("sample.log"):
            analyze()

observer = Observer()
observer.schedule(Handler(), path=".", recursive=False)

observer.start()

print("👀 Monitoring log file in real-time...")

try:
    while True:
        time.sleep(2)
except KeyboardInterrupt:
    observer.stop()

observer.join()
