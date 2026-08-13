SOC Log Analyzer



A Python-based Security Operations Center (SOC) log analysis tool that detects suspicious login activity, identifies potential brute-force attacks, analyzes failed login attempts, and generates a security report.



Features



\- Parses authentication and security logs

\- Counts successful and failed login attempts

\- Identifies failed login attempts by username

\- Groups failed login attempts by IP address

\- Detects potential brute-force attacks

\- Identifies suspicious IP addresses

\- Assigns security severity levels

\- Generates alert status messages

\- Provides automated security recommendations

\- Generates a timestamped security report

\- Uses a configurable brute-force detection threshold



Detection Logic



The analyzer uses the following severity levels:



| Severity | Condition |

|----------|-----------|

| LOW | Fewer than 2 failed attempts |

| MEDIUM | 2 failed attempts |

| HIGH | 3 or more failed attempts |



The brute-force threshold can be configured using:



```python

BRUTE\_FORCE\_THRESHOLD = 3

