# Detection Engine

A rule-based detection engine that evaluates YAML detection rules against Windows
event logs and measures coverage against MITRE ATT&CK.

The engine parses `.evtx` files, matches events against a rule set, and reports
coverage per ATT&CK tactic. It is built around the idea that a coverage number is
only useful if you know how much of it is real.

## Coverage

Measured against 278 attack samples from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES),
using 27 rules.

```
TACTIC                        FILES  CAUGHT  COVERAGE
------------------------------------------------------
AutomatedTestingTools             8       7       88%
Command and Control               6       1       17%
Credential Access                39      21       54%
Defense Evasion                  36      12       33%
Discovery                        11       4       36%
Execution                        34      19       56%
Lateral Movement                 47      16       34%
Other                             8       0        0%
Persistence                      22      10       45%
Privilege Escalation             66      25       38%
Uncategorized                     1       0        0%
------------------------------------------------------
OVERALL                         278     115       41%

HEADLINE COVERAGE                      41%
SUBSTANTIVE COVERAGE                   30%
(files carried by low-confidence only)     31

RULE                                     FILES HIT
---------------------------------------------------
browser_spawns_shell                             4
create_remote_thread (low conf)                 10
credential_dump_commandline                      3
discovery_recon_burst                            3
event_log_cleared (low conf)                    26
lolbin_download                                  2
lsass_process_access                            13
lsass_query_only_access (low conf)               1
mshta_remote_execution                           2
ntds_extraction                                  1
powershell_suspicious_flags                      5
psexec_lateral_movement                          4
recovery_destruction                             1
registry_hive_dump                               1
registry_run_key_persistence                     9
regsvr32_scriptlet                               5
rundll32_lolbas_export                          11
scheduled_task_creation                          8
service_creation_commandline                     1
service_installed                                2
uac_bypass_parent                                8
uac_bypass_registry                              6
unbacked_call_trace                             24
wmi_event_subscription                           3
wmi_remote_execution                             1
wmiprvse_spawned_shell                           9
xsl_script_execution                             4
```

Two figures are reported because they disagree, and the disagreement is the point.

**Headline coverage** counts any file where at least one rule fired.
**Substantive coverage** excludes files caught only by rules marked
`confidence: low` - rules that fire on activity that is real but not
characteristic of the technique the sample demonstrates.

Eleven points of apparent coverage are hollow. Reporting only the headline figure
would overstate what this rule set actually detects by more than a third.

## Design

**Rules are data, not code.** Each detection is a YAML file in `rules/`. The engine
has no knowledge of any specific rule. Adding a detection means adding a file.

**Matching semantics.** Fields within a rule are ANDed; values within a field are
ORed. Seven operators are supported:

| Operator | Behaviour |
|---|---|
| `equals` | exact string match |
| `equals_any` | exact match against a list |
| `contains_any` | substring match, any of |
| `contains_all` | substring match, all of |
| `not_contains` | exclusion |
| `bitmask_any` | hex value has any of these bits set |
| `bitmask_none` | hex value has none of these bits set |

The bitmask operators exist because Windows access rights cannot be matched as
strings: `0x1410` and `0x1FFFFF` both grant `PROCESS_VM_READ` but share no
substring.

**Log source scoping.** Event IDs are only unique within a provider, not globally.
Rules that match on event ID alone carry a `logsource` block constraining channel
or provider.

**Threshold rules.** Some behaviour is only suspicious in aggregate. A rule may
declare a `threshold` requiring N distinct values of a field across all matching
events, evaluated as a second stage after per-event matching.

## Findings

### 1. Most of my coverage number was not real

My first full run reported 45% coverage, and I nearly wrote that number down and
moved on. What stopped me was the per-rule breakdown: my log-clearing rule had
fired on 26 of 278 samples. Clearing the event log is a deliberate anti-forensic
act, so a rate of nearly one in ten looked wrong. When I listed the files, they
included samples named for Kerberos password spraying, BloodHound enumeration and
WMI lateral movement - none of which have any reason to involve log clearing.

I checked where in each file the matching event appeared. All 26 were the first
event in the file, with no exceptions. The person who captured this corpus cleared
the event log before each recording so the capture would be clean. My rule was
detecting the collection methodology, not the attack. Only two samples in the whole
corpus genuinely demonstrate adversary log clearing.

The rule itself is correct - I did not want to delete a detection for real
behaviour because one dataset was contaminated. Instead I added a `confidence`
field to the rule schema and marked the rules that fire on incidental activity. The
tool now reports two figures: headline coverage, which counts any file where a rule
fired, and substantive coverage, which excludes files carried only by
low-confidence rules. On the final rule set that is 41% against 30%. Eleven points
of my original number were hollow.

I kept this as the default output rather than a debug option, because the version
of this mistake that matters is a security team looking at a green dashboard and
believing techniques are covered when they are not.

### 2. Tightening a rule for precision quietly cost me a real detection

My LSASS rule originally matched any handle opened to `lsass.exe`. That overfires
badly - antivirus, inventory tools and Windows components open handles to LSASS
constantly, and in production this rule would bury an analyst.

I tightened it using the `GrantedAccess` field, which is a bitmask of the rights
the handle was granted. My reasoning was that credential dumping requires reading
LSASS memory, so `PROCESS_VM_READ` (0x10) must be set; handles granting only query
rights cannot reach credential material. This required adding a `bitmask_any`
operator to the engine, because `0x1410` and `0x1FFFFF` both grant read access but
share no substring, so string matching cannot express the condition.

Coverage barely moved - 14 files down to 13 - so I checked which file I had lost
rather than assuming the change was harmless. It was
`ppl_bypass_ppldump_knowdll_hijack`. PPLdump is a real credential dumping tool that
defeats Protected Process Light, and in that sample its only handles to LSASS were
`0x1000`, query rights only. My precision improvement had traded away a true
positive for a technique I specifically wanted to catch.

I did not want to pick a side of that trade, so I split the detection into two
tiers: a critical rule requiring memory access rights, and a separate
low-confidence rule for query-only handles. The signal is retained without
inflating the high-confidence alert count.

### 3. My own exclusion list hid the strongest event in the file

Investigating the sample above, I found something worse than the missing PPLdump
handles. The same file contained `services.exe` opening LSASS with
`PROCESS_ALL_ACCESS` (`0x001fffff`) - full rights, including memory read. That was
the actual credential access, and it was the highest-signal event in the capture.

My rule did not fire on it, because I had put `services.exe` on the `SourceImage`
exclusion list myself. That exclusion was not unreasonable in isolation:
`services.exe` is a signed SYSTEM process that touches LSASS in normal operation,
and without exclusions like it the rule is unusable. But the attack in this sample
was a KnownDlls hijack, which gets attacker code executing inside a trusted process
- so my allowlist was protecting the attacker.

The general lesson is that path-based allowlisting cannot survive code injection
into an allowlisted process, and getting code into a trusted process is a standard
objective rather than an exotic one. To fix this properly I would need signature or
hash verification on the source process, correlation with image load events to spot
the hijacked DLL, or exclusion by process lineage rather than by path. I recorded
the failure in the rule's tuning notes rather than removing the exclusions, since
removing them would make the rule unusable and would not address the underlying
weakness.

### 4. Some behaviour is only suspicious in aggregate

My reconnaissance rule matched any single enumeration utility - `whoami.exe`,
`nltest.exe`, `systeminfo.exe` and similar. It fired on 21 files and told me almost
nothing, because administrators run these commands constantly. A single `whoami` is
not an attack.

The real signal is several distinct utilities appearing together, which my engine
could not express: it evaluated one event at a time and had no way to reason about
a set of matches. I added a `threshold` stage that runs after per-event matching
and requires N distinct values of a chosen field before the rule fires. Rewritten
to require three distinct recon binaries, the rule dropped from 21 files to 3, and
the number of files carried only by low-confidence rules fell from 41 to 31.

Headline coverage fell from 45% to 41% as a result, while substantive coverage held
at 30%. I removed eighteen detections that were not telling me anything and lost no
real ones, and the two figures moved closer together - which is the outcome I
wanted, since the gap between them is the part of the number I cannot trust.

I am treating file boundary as a proxy for a time window here. Against live
telemetry this would need to be a windowed, per-host correlation, which this corpus
cannot support because it has no continuous timeline.

## Limitations

- **Precision is unmeasurable against this corpus.** Every sample contains attack
  activity; there is no benign baseline. Improvements to rule precision are
  directional, not quantified.
- **Threshold rules use file boundary as a proxy for a time window.** The corpus
  provides no continuous timeline. Against live telemetry these rules would need
  rewriting as windowed, per-host correlations.
- **No sequence or cross-host correlation.** Each event is evaluated independently
  apart from the threshold stage.
- **Windows Sysmon and Security channel only.**

## Running it

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git samples
python matrix.py samples
```

Single file:

```bash
python engine.py "samples/Execution/exec_driveby_cve-2018-15982_sysmon_1_10.evtx"
```

## Layout

```
engine.py    rule loading, matching, threshold evaluation
parse.py     EVTX to flat dictionaries
matrix.py    corpus scan and coverage reporting
peek.py      raw XML inspection for a single file
rules/       27 detection rules
```

The sample corpus is not vendored into this repository.
