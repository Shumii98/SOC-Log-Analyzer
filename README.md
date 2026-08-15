**SOC Log Analyzer**



A Python-based Security Operations Center (SOC) log analysis tool that analyzes authentication logs to identify suspicious login activity, detect potential brute-force attacks, classify security severity, and generate actionable security reports.



**Features**

* Parses authentication and security logs
* Analyzes successful and failed login attempts
* Groups failed attempts by username and IP address
* Detects potential brute-force attacks
* Identifies suspicious IP addresses
* Assigns LOW, MEDIUM, and HIGH severity levels
* Generates security alerts and recommendations
* Creates timestamped security reports
* Uses a configurable brute-force detection threshold



**Detection Logic**



The analyzer evaluates failed login activity and assigns severity based on the number of attempts:



| **Severity** | **Condition**                    |

| -------- | ---------------------------- |

| LOW      | Fewer than 2 failed attempts |

| MEDIUM   | 2 failed attempts            |

| HIGH     | 3 or more failed attempts    |



The brute-force detection threshold can be configured in the analyzer:



python

BRUTE\_FORCE\_THRESHOLD = 3



**Technologies Used**



* Python 
* Regular Expressions (`re`)
* File and log processing
* Rule-based threat detection
* Security event analysis



**Project Structure**



```text

SOC-Log-Analyzer/

├── logs/

├── reports/

├── screenshots/

├── src/

├── .gitignore

├── LICENSE

├── README.md

└── requirements.txt

```



**How It Works**



Authentication Logs

&#x20;       |

&#x20;       v

Log Parsing \& Analysis

&#x20;       |

&#x20;       v

Failed Login Detection

&#x20;       |

&#x20;       v

IP / Username Aggregation

&#x20;       |

&#x20;       v

Brute-Force Detection

&#x20;       |

&#x20;       v

Severity Classification

&#x20;       |

&#x20;       v

Security Report \& Recommendations



**Use Case**



This project demonstrates fundamental SOC analyst and blue-team skills, including:



* Security log analysis
* Authentication event monitoring
* Suspicious activity detection
* Brute-force identification
* Alert severity classification
* Basic security reporting



**Security Note**



This project is intended for educational and defensive cybersecurity purposes. It demonstrates rule-based log analysis and should not be considered a replacement for a production SIEM or enterprise security monitoring platform.



**License**



This project is licensed under the MIT License.



