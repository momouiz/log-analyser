# Log Analyser

A Python script that reads a Linux `auth.log` file and looks for suspicious logins.

**Only use this on logs from systems you own or have permission to analyse.**

## What it does

It goes through every SSH login line (`Failed password` / `Accepted password`) and flags:

- **Possible brute force**: 5 or more failed logins from the same IP within 5 minutes.
- **Logins at unusual hours**: successful logins between midnight and 5am.
- **Success after many failures**: an IP that gets in after 3 or more failed attempts. This could mean a password was guessed.

It prints a summary (number of fails/successes, top IPs, alerts) and can save it as a `.txt` or `.csv` file.

You can change the limits at the top of `log_analyser.py` (`FAIL_LIMIT`, `WINDOW_MINUTES` etc).

## Why I built it

I'm interested in cyber security, and one of the first things I read about was how attackers brute force SSH. I wanted to see if I could spot it myself in a log file, a bit like a very simple version of what a SOC analyst or a tool like fail2ban does.

## How to run it

You need Python 3. There are no extra packages.

```
python log_analyser.py sample_auth.log
python log_analyser.py sample_auth.log -o report.txt
python log_analyser.py sample_auth.log -o report.csv
```

On Linux the real log is usually `/var/log/auth.log` (you need sudo to read it). auth.log doesn't store the year, so use `--year 2025` if the log is from a different year.

`sample_auth.log` is a **fake** log I made up for testing. All the IPs are from the documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x), so none of them are real.

## Example output

```
==================================================
AUTH LOG REPORT for sample_auth.log
==================================================
Login events found: 33
Failed logins:      25
Successful logins:  8
Unique IPs:         6

Top IPs by failed logins:
  203.0.113.45      12
  203.0.113.9       7
  198.51.100.77     4
  192.0.2.11        2

ALERTS (5)
--------------------------------------------------
[!] Nov 12 02:11:00  POSSIBLE BRUTE FORCE
    ip: 203.0.113.45 - 12 failed logins within 5 mins
[!] Nov 12 03:07:12  LOGIN AT UNUSUAL HOUR
    ip: 198.51.100.77 - user charlie logged in at 03:07
[!] Nov 12 03:07:12  SUCCESS AFTER MANY FAILURES
    ip: 198.51.100.77 - user charlie got in after 4 failed attempts
[!] Nov 12 22:48:00  POSSIBLE BRUTE FORCE
    ip: 203.0.113.9 - 7 failed logins within 5 mins
[!] Nov 12 22:49:40  SUCCESS AFTER MANY FAILURES
    ip: 203.0.113.9 - user admin got in after 7 failed attempts
```

`192.0.2.11` (bob mistyping his password twice) doesn't get flagged. That's what I wanted, because 2 typos isn't an attack.

## What I learned

- How auth.log is laid out, and using regex to pull the user and IP out of each line.
- Using a sliding time window. My first idea was just counting total fails per IP, but that flags someone who mistypes their password once a day for a week.
- A slow attacker (198.51.100.77 in the sample) doesn't trigger the brute force rule, but still gets caught by the "success after failures" rule. So it's good to have more than one check.
- auth.log has no year in the timestamp, which caught me out.

## TODO

- Support other log formats (e.g. Windows event logs).
- Ignore a list of trusted IPs.
- Work out the country for each IP.
