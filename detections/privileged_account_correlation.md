# Privileged Account Correlation Detection

## Detection Summary

- **Platform:** Windows
- **Log source:** Windows Security events
- **Event IDs:** 4720 and 4732
- **MITRE ATT&CK:** T1136.001 and T1098.007
- **Severity:** High
- **Correlation window:** Five minutes
- **Events processed:** Four
- **Alerts generated:** One
- **Automated tests:** Four passed

## Detection Logic

The detector correlates a newly created Windows account with the same account being added to the local Administrators group within five minutes.

The account is matched using the computer name and security identifier to reduce false correlations between unrelated events.

## Investigation Guidance

1. Confirm who created the account and whether the action was approved.
2. Review the account name, SID, creation time, and affected endpoint.
3. Determine why the account was added to the Administrators group.
4. Search for successful logons and process activity involving the account.
5. Disable the account and remove its privileges if unauthorized.
6. Review the administrator account responsible for the changes.

## False Positives

- Approved administrator provisioning
- Authorized service-account creation
- Endpoint-management software
- Legitimate help-desk activity
