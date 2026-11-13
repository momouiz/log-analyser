# log analyser
# reads a linux auth.log style file and looks for suspicious login activity
# usage: python log_analyser.py sample_auth.log

import argparse
import csv
import re
from datetime import datetime

# settings - change these if you want it to be more or less strict
FAIL_LIMIT = 5          # this many failed logins...
WINDOW_MINUTES = 5      # ...within this many minutes = possible brute force
NIGHT_START = 0         # logins between these hours count as "unusual"
NIGHT_END = 5
SUCCESS_AFTER_FAILS = 3 # a success after at least this many fails is flagged

# auth.log lines look like:
# Nov 12 08:15:01 server1 sshd[1234]: Failed password for root from 203.0.113.5 port 50000 ssh2
failed_pattern = re.compile(r"Failed password for (invalid user )?(\S+) from (\S+)")
success_pattern = re.compile(r"Accepted (password|publickey) for (\S+) from (\S+)")


def parse_time(line, year):
    # the first 15 characters are the date and time e.g. "Nov 12 08:15:01"
    # auth.log doesnt include the year so i have to add it myself
    text = line[:15]
    try:
        return datetime.strptime(str(year) + " " + text, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def read_log(filename, year):
    events = []
    f = open(filename, "r", errors="ignore")
    for line in f:
        line = line.strip()
        if line == "":
            continue
        time = parse_time(line, year)
        if time is None:
            continue

        m = failed_pattern.search(line)
        if m:
            events.append({"time": time, "type": "fail", "user": m.group(2), "ip": m.group(3)})
            continue

        m = success_pattern.search(line)
        if m:
            events.append({"time": time, "type": "success", "user": m.group(2), "ip": m.group(3)})
    f.close()
    return events


def find_brute_force(events):
    # group the failed login times by ip
    fails_by_ip = {}
    for e in events:
        if e["type"] == "fail":
            if e["ip"] not in fails_by_ip:
                fails_by_ip[e["ip"]] = []
            fails_by_ip[e["ip"]].append(e["time"])

    alerts = []
    for ip in fails_by_ip:
        times = sorted(fails_by_ip[ip])
        # sliding window - for each fail, count how many fails happened
        # in the next WINDOW_MINUTES
        best = 0
        best_start = None
        for i in range(len(times)):
            count = 0
            for j in range(i, len(times)):
                diff = (times[j] - times[i]).total_seconds()
                if diff <= WINDOW_MINUTES * 60:
                    count += 1
                else:
                    break
            if count > best:
                best = count
                best_start = times[i]
        if best >= FAIL_LIMIT:
            alerts.append({
                "alert": "possible brute force",
                "ip": ip,
                "time": best_start,
                "details": str(best) + " failed logins within " + str(WINDOW_MINUTES) + " mins",
            })
    return alerts


def find_unusual_hours(events):
    alerts = []
    for e in events:
        if e["type"] == "success":
            hour = e["time"].hour
            if hour >= NIGHT_START and hour < NIGHT_END:
                alerts.append({
                    "alert": "login at unusual hour",
                    "ip": e["ip"],
                    "time": e["time"],
                    "details": "user " + e["user"] + " logged in at " + e["time"].strftime("%H:%M"),
                })
    return alerts


def find_success_after_fails(events):
    # keep a running count of fails for each ip, reset it when they get in
    alerts = []
    fail_count = {}
    for e in sorted(events, key=lambda x: x["time"]):
        ip = e["ip"]
        if e["type"] == "fail":
            fail_count[ip] = fail_count.get(ip, 0) + 1
        else:
            if fail_count.get(ip, 0) >= SUCCESS_AFTER_FAILS:
                alerts.append({
                    "alert": "success after many failures",
                    "ip": ip,
                    "time": e["time"],
                    "details": "user " + e["user"] + " got in after " + str(fail_count[ip]) + " failed attempts",
                })
            fail_count[ip] = 0
    return alerts


def print_report(events, alerts, filename):
    fails = [e for e in events if e["type"] == "fail"]
    successes = [e for e in events if e["type"] == "success"]
    ips = set(e["ip"] for e in events)

    lines = []
    lines.append("=" * 50)
    lines.append("AUTH LOG REPORT for " + filename)
    lines.append("=" * 50)
    lines.append("Login events found: " + str(len(events)))
    lines.append("Failed logins:      " + str(len(fails)))
    lines.append("Successful logins:  " + str(len(successes)))
    lines.append("Unique IPs:         " + str(len(ips)))
    lines.append("")

    # top ips by number of failed logins
    counts = {}
    for e in fails:
        counts[e["ip"]] = counts.get(e["ip"], 0) + 1
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
    lines.append("Top IPs by failed logins:")
    for ip, c in top:
        lines.append("  " + ip.ljust(18) + str(c))
    lines.append("")

    lines.append("ALERTS (" + str(len(alerts)) + ")")
    lines.append("-" * 50)
    if len(alerts) == 0:
        lines.append("nothing suspicious found :)")
    for a in alerts:
        lines.append("[!] " + a["time"].strftime("%b %d %H:%M:%S") + "  " + a["alert"].upper())
        lines.append("    ip: " + a["ip"] + " - " + a["details"])

    report = "\n".join(lines)
    print(report)
    return report


def save_csv(alerts, filename):
    f = open(filename, "w", newline="")
    writer = csv.writer(f)
    writer.writerow(["time", "alert", "ip", "details"])
    for a in alerts:
        writer.writerow([a["time"].strftime("%Y-%m-%d %H:%M:%S"), a["alert"], a["ip"], a["details"]])
    f.close()


def main():
    parser = argparse.ArgumentParser(description="Look for suspicious logins in an auth.log file")
    parser.add_argument("logfile", help="path to the auth.log file")
    parser.add_argument("-o", "--output", help="save the report to a .txt or .csv file")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year the log is from (auth.log doesnt store it)")
    args = parser.parse_args()

    events = read_log(args.logfile, args.year)
    if len(events) == 0:
        print("No login events found in " + args.logfile)
        return

    alerts = find_brute_force(events) + find_unusual_hours(events) + find_success_after_fails(events)
    alerts.sort(key=lambda a: a["time"])

    report = print_report(events, alerts, args.logfile)

    if args.output:
        if args.output.endswith(".csv"):
            save_csv(alerts, args.output)
        else:
            f = open(args.output, "w")
            f.write(report + "\n")
            f.close()
        print("\nReport saved to " + args.output)


if __name__ == "__main__":
    main()
