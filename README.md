# apt41-lsass-detections

Sigma rules for LSASS credential dumping (T1003.001), one of APT41's core techniques, plus a replay test that shows why the first version of my detection didn't work, and an APT41 coverage map against the current ATT&CK release.

## The mistake

In my APT41 investigation I recommended alerting when a process opens `lsass.exe` with "high/full access rights (e.g. 0x1F0FFF)". When I checked that value:

- **`0x1F0FFF` is the pre-Vista value of `PROCESS_ALL_ACCESS`.** It's `STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF`. Since Vista the constant is `0x1FFFFF`.
- **Mimikatz doesn't ask for full access.** `kuhl_m_sekurlsa.c` opens LSASS with `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION` on Vista and later, which is `0x1010`.

Replaying labelled sample events through both versions (`python tools/evaluate.py`):

```
sample                           label     original  new rules
--------------------------------------------------------------------------------
mimikatz-sekurlsa                malicious -         lsass_access_dumping_rights
full-access-dumper-modern-sdk    malicious -         lsass_access_dumping_rights
query-plus-read                  malicious -         lsass_access_dumping_rights
comsvcs-minidump                 malicious -         lsass_dump_comsvcs_minidump
comsvcs-ordinal                  malicious -         lsass_dump_comsvcs_minidump
procdump-renamed                 malicious -         lsass_dump_procdump
dump-file                        malicious -         lsass_dump_file_created
old-tool-xp-all-access           malicious HIT       lsass_access_dumping_rights
defender-scan                    benign    -         -
svchost-query                    benign    -         -
user-tool-sync-only              benign    -         -
normal-rundll32                  benign    -         -
procdump-other-process           benign    -         -
wer-crash-dump                   benign    -         -

LSASS handle-access samples: original rule 1/4, new rules 4/4
new rules:     8/8 malicious samples detected, 0/6 benign samples alerted
```

The original rule only ever looked at handle access, so the fair comparison is the first line: **1 of 4**.

The sample events are synthetic, written to match documented behaviour (Mimikatz source, Microsoft's access-rights page, MITRE CAR-2019-04-004). They are not captured telemetry. They test the rule logic, not real-world noise.

## The rules

| Rule | Data | What it looks for |
|---|---|---|
| `lsass_access_dumping_rights` | Sysmon EID 10 | memory-read rights on lsass (`0x1010`, `0x1410`, `0x1418`, `0x1438`, `0x143a`, `0x1FFFFF`, `0x1F0FFF`) from outside system and security-product paths |
| `lsass_dump_comsvcs_minidump` | process creation | `rundll32 comsvcs.dll MiniDump`, including the `#24` ordinal |
| `lsass_dump_procdump` | process creation | `-ma` / `-mp` against lsass. Matches on the command line, so a renamed binary is still caught |
| `lsass_dump_file_created` | file creation | `*lsass*.dmp` written anywhere except the Windows Error Reporting folder |

`conversions/` holds pySigma output for Microsoft Defender XDR / Sentinel (KQL) and Splunk. The handle-access rule has no KQL version, because Defender's Advanced Hunting tables don't record Sysmon-style `GrantedAccess`. Use Sysmon for that one.

SigmaHQ already has 79 rules tagged T1003.001, some broader than these. These four are narrow on purpose, so each one can be traced to a specific behaviour and tested.

## APT41 in ATT&CK v20

`tools/apt41_coverage.py` reads the ATT&CK Enterprise STIX bundle and a SigmaHQ checkout and writes `reports/apt41-coverage.md`, plus a Navigator layer (`layers/apt41-sigma-coverage.json`) scored by SigmaHQ rule count.

- **82** techniques and sub-techniques are mapped directly to APT41 (G0096) in ATT&CK v20. My original notes estimated "40+" from the Navigator.
- Since v19 (April 2026), Defense Evasion is split into Stealth and Defense Impairment. In v20, APT41's largest tactic is **Stealth** (17), followed by Persistence and Discovery (12 each).
- **8** of the 82 have no SigmaHQ rule tagged with that ID. Some, such as T1098.007 or T1071.002, are covered one level up by parent-technique rules. Others, such as T1480.001 Environmental Keying or T1684.001 Impersonation, have nothing.
- **Renumbering:** T1684.001 replaced T1656. The tool also counts rules tagged with old IDs, so renumbering doesn't create fake gaps.

Data: ATT&CK Enterprise 20.0 (2026-10-13), SigmaHQ @ `ccbb036`.

## Run it

```bash
pip install -r requirements.txt
python tools/evaluate.py        # replay samples through original and new rules
python tools/convert.py         # regenerate KQL / SPL
pytest                          # 23 tests, incl. "conversions are up to date"

# coverage report (needs the two downloads)
python tools/apt41_coverage.py --attack enterprise-attack-20.0.json --sigma ./sigma
```

## Mitigations that make these alerts rarer

Credential Guard (M1043) and LSA protection / RunAsPPL (M1025) stop most user-mode dumping outright. The ASR rule *Block credential stealing from the Windows local security authority subsystem* covers the same ground on Defender. Detections are for when those aren't deployed everywhere, which is most networks.

## License

MIT
