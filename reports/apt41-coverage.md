# APT41 (G0096) technique coverage in SigmaHQ

ATT&CK Enterprise 20.0, SigmaHQ @ `ccbb036`.

- Techniques and sub-techniques mapped directly to APT41: **82**
- With at least one SigmaHQ rule (counting sub-technique rules for parents): **74**
- With no rule tagged with that ID: **8**

## By tactic

| Tactic | Techniques |
|---|---|
| stealth | 17 |
| persistence | 12 |
| discovery | 12 |
| execution | 10 |
| privilege-escalation | 9 |
| command-and-control | 9 |
| credential-access | 7 |
| defense-impairment | 6 |
| initial-access | 5 |
| lateral-movement | 4 |
| collection | 4 |
| reconnaissance | 3 |
| impact | 2 |
| resource-development | 1 |
| exfiltration | 1 |

## No SigmaHQ rule tagged with this ID

Rules tagged only with the parent technique are not counted here, so for sub-techniques the parent column shows what exists one level up.

| ID | Technique | Tactic | Rules on parent |
|---|---|---|---|
| T1071.002 | File Transfer Protocols | command-and-control | 7 |
| T1098.007 | Additional Local or Domain Groups | persistence, privilege-escalation | 33 |
| T1104 | Multi-Stage Channels | command-and-control | - |
| T1480.001 | Environmental Keying | stealth | 0 |
| T1496.001 | Compute Hijacking | impact | 13 |
| T1595.003 | Wordlist Scanning | reconnaissance | 3 |
| T1596.005 | Scan Databases | reconnaissance | 0 |
| T1684.001 | Impersonation (was T1656) | stealth | 0 |

## All techniques

| ID | Technique | Tactic | Rules (exact) | Rules (incl. subs) |
|---|---|---|---|---|
| T1003.001 | LSASS Memory | credential-access | 79 | 79 |
| T1003.002 | Security Account Manager | credential-access | 28 | 28 |
| T1003.003 | NTDS | credential-access | 24 | 24 |
| T1005 | Data from Local System | collection | 14 | 14 |
| T1008 | Fallback Channels | command-and-control | 4 | 4 |
| T1012 | Query Registry | discovery | 13 | 13 |
| T1014 | Rootkit | stealth | 1 | 1 |
| T1016 | System Network Configuration Discovery | discovery | 11 | 11 |
| T1018 | Remote System Discovery | discovery | 17 | 17 |
| T1021.001 | Remote Desktop Protocol (was T1076) | lateral-movement | 16 | 16 |
| T1021.002 | SMB/Windows Admin Shares (was T1077) | lateral-movement | 38 | 38 |
| T1027 | Obfuscated Files or Information | stealth | 95 | 128 |
| T1027.002 | Software Packing (was T1045) | stealth | 1 | 1 |
| T1030 | Data Transfer Size Limits | exfiltration | 2 | 2 |
| T1033 | System Owner/User Discovery | discovery | 30 | 30 |
| T1036.004 | Masquerade Task or Service | stealth | 3 | 3 |
| T1036.005 | Match Legitimate Resource Name or Location | stealth | 24 | 24 |
| T1037 | Boot or Logon Initialization Scripts | persistence, privilege-escalation | 0 | 4 |
| T1046 | Network Service Discovery | discovery | 20 | 20 |
| T1047 | Windows Management Instrumentation | execution | 52 | 52 |
| T1049 | System Network Connections Discovery | discovery | 9 | 9 |
| T1053.005 | Scheduled Task | execution, persistence, privilege-escalation | 52 | 52 |
| T1055 | Process Injection | stealth, privilege-escalation | 37 | 55 |
| T1056.001 | Keylogging | collection, credential-access | 3 | 3 |
| T1059.001 | PowerShell (was T1086) | execution | 222 | 222 |
| T1059.003 | Windows Command Shell | execution | 46 | 46 |
| T1059.004 | Unix Shell | execution | 19 | 19 |
| T1069 | Permission Groups Discovery | discovery | 3 | 35 |
| T1070.003 | Clear Command History (was T1146) | stealth | 9 | 9 |
| T1070.004 | File Deletion (was T1107) | stealth | 15 | 15 |
| T1071.001 | Web Protocols | command-and-control | 42 | 42 |
| T1071.002 | File Transfer Protocols | command-and-control | 0 | 0 |
| T1071.004 | DNS | command-and-control | 18 | 18 |
| T1078 | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | 51 | 102 |
| T1082 | System Information Discovery | discovery | 33 | 33 |
| T1083 | File and Directory Discovery | discovery | 24 | 24 |
| T1087.001 | Local Account | discovery | 13 | 13 |
| T1087.002 | Domain Account | discovery | 21 | 21 |
| T1090 | Proxy | command-and-control | 22 | 34 |
| T1098.007 | Additional Local or Domain Groups | persistence, privilege-escalation | 0 | 0 |
| T1102.001 | Dead Drop Resolver | command-and-control | 4 | 4 |
| T1104 | Multi-Stage Channels | command-and-control | 0 | 0 |
| T1105 | Ingress Tool Transfer | command-and-control | 87 | 87 |
| T1110 | Brute Force | credential-access | 23 | 29 |
| T1112 | Modify Registry | defense-impairment, persistence | 97 | 97 |
| T1133 | External Remote Services | persistence, initial-access | 20 | 20 |
| T1135 | Network Share Discovery | discovery | 7 | 7 |
| T1136.001 | Local Account | persistence | 18 | 18 |
| T1190 | Exploit Public-Facing Application | initial-access | 149 | 149 |
| T1195.002 | Compromise Software Supply Chain | initial-access | 17 | 17 |
| T1197 | BITS Jobs | stealth, persistence, execution | 16 | 16 |
| T1203 | Exploitation for Client Execution | execution | 35 | 35 |
| T1213.003 | Code Repositories | collection | 5 | 5 |
| T1218.001 | Compiled HTML File (was T1223) | stealth | 6 | 6 |
| T1218.011 | Rundll32 (was T1085) | stealth | 43 | 43 |
| T1480.001 | Environmental Keying | stealth | 0 | 0 |
| T1484.001 | Group Policy Modification | defense-impairment, privilege-escalation | 6 | 6 |
| T1486 | Data Encrypted for Impact | impact | 17 | 17 |
| T1496.001 | Compute Hijacking | impact | 0 | 0 |
| T1542.003 | Bootkit (was T1067) | stealth, persistence | 1 | 1 |
| T1543.003 | Windows Service (was T1031, T1050) | persistence, privilege-escalation | 47 | 47 |
| T1546.008 | Accessibility Features (was T1015) | privilege-escalation, persistence | 6 | 6 |
| T1547.001 | Registry Run Keys / Startup Folder (was T1060) | persistence, privilege-escalation | 39 | 39 |
| T1550.002 | Pass the Hash (was T1075) | lateral-movement | 5 | 5 |
| T1553.002 | Code Signing (was T1116) | defense-impairment | 1 | 1 |
| T1555 | Credentials from Password Stores | credential-access | 8 | 22 |
| T1555.003 | Credentials from Web Browsers (was T1503) | credential-access | 8 | 8 |
| T1560.001 | Archive via Utility | collection | 17 | 17 |
| T1566.001 | Spearphishing Attachment (was T1193) | initial-access | 24 | 24 |
| T1568.002 | Domain Generation Algorithms (was T1483) | command-and-control | 2 | 2 |
| T1569.002 | Service Execution (was T1035) | execution | 43 | 43 |
| T1570 | Lateral Tool Transfer | lateral-movement | 6 | 6 |
| T1574.001 | DLL (was T1038, T1574.002) | stealth, execution | 93 | 93 |
| T1574.006 | Dynamic Linker Hijacking | stealth, execution | 2 | 2 |
| T1588.002 | Tool | resource-development | 9 | 9 |
| T1595.002 | Vulnerability Scanning | reconnaissance | 1 | 1 |
| T1595.003 | Wordlist Scanning | reconnaissance | 0 | 0 |
| T1596.005 | Scan Databases | reconnaissance | 0 | 0 |
| T1599 | Network Boundary Bridging | defense-impairment | 0 | 1 |
| T1684.001 | Impersonation (was T1656) | stealth | 0 | 0 |
| T1685 | Disable or Modify Tools (was T1562.001, T1562.006, T1562, T1089, T1054) | defense-impairment | 168 | 212 |
| T1685.005 | Clear Windows Event Logs (was T1070.001) | defense-impairment | 8 | 8 |
