# SSH Brute-Force Detection

## Detection Summary

- **Platform:** Linux
- **Log source:** SSH authentication logs
- **MITRE ATT&CK:** T1110.001 — Password Guessing
- **Severity:** Medium
- **Threshold:** Five failed login attempts
- **Detected source:** 203.0.113.50
- **Failed attempts:** Five
- **Automated tests:** Four passed

## Detection Logic

The Python detector extracts source IP addresses from failed SSH login events and counts the attempts associated with each address.

An alert is generated when one source IP reaches five or more failed authentication attempts.

## Investigation Guidance

1. Confirm whether the source IP is approved.
2. Review the targeted usernames.
3. Search for a successful login after the failures.
4. Check for additional activity from the same address.
5. Block the source and reset affected credentials when necessary.

## False Positives

- A legitimate user repeatedly entering the wrong password
- Approved penetration testing
- Authorized vulnerability scanning
