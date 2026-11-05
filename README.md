# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | 60 | 54 | 1 | 5 |
| file_log.csv | 35 | 30 | 1 | 4 |

- SHA-256 check outcome and what it establishes: Both CSV files passed the SHA-256 checks against the supplied evidence manifest. This establishes that the files match the supplied baseline byte-for-byte. It does not establish the authenticity, origin or completeness of the original evidence.
- One rejected event ID and the exact rejection reason: Authentication event A900 was rejected because its timestamp was invalid: Invalid isoformat string: 'not-a-time'
- Number of flagged successful sessions: 3 (A005, A018 and A014)

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| A005 | analyst01 | S-104 | A002, A003, A004 | F001, F002, F003 | 3 | 5,509,120 |
| A018 | analyst02 | S-304 | A015, A016, A017 | F013 | 1 | 2,048 |
| A014 | backup_svc | S-204 | A011, A012, A013 | None | 0 | 0 |

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv A002 | 2026-10-20T08:58:00Z | 2026-10-20T08:58:00Z | Failed login for analyst01 |
| auth_log.csv A003 | 2026-10-20T09:00:00Z | 2026-10-20T09:00:00Z | Failed login for analyst01 |
auth_log.csv A004 | 2026-10-20T10:01:00+01:00 | 2026-10-20T09:01:00Z | Failed login for analyst01 |
| auth_log.csv A005 | 2026-10-20T09:03:00Z | 2026-10-20T09:03:00Z | Successful login, session S-104 |
| file_log.csv F001 | 2026-10-20T09:05:00Z | 2026-10-20T09:05:00Z | Successful download, 5,242,880 bytes |
| file_log.csv F002 | 2026-10-20T10:07:00+01:00 | 2026-10-20T09:07:00Z | Successful download, 262,144 bytes |
| file_log.csv F003 | 2026-10-20T09:13:00Z | 2026-10-20T09:13:00Z | Successful download, 4,096 bytes |

- Manual sum of download bytes, showing the addition: 
5,242,880 + 262,144 + 4,096 = 5,509,120 bytes

- A001 versus A002: which qualifies for the A005 window and why? 
A002 qualifies because its timestamp is exactly the five-minute lower boundary (08:58:00 UTC). A001 at 08:57:59 UTC is one second outside the window and is excluded

- F003 versus F004: which qualifies for the A005 follow-up and why? 
F003 qualifies because it occurs exactly at the ten-minute upper boundary (09:13:00 UTC). F004 at 09:13:01 UTC is one second outside the window and is excluded

- Why F005 is excluded even though the account matches:
F005 belongs to session S-OTHER rather than S-104. The correlation rule requires username, host AND session ID to match

- One +01:00 timestamp and its equivalent UTC time:
F002: 10:07:00+01:00 is equivalent to 09:07:00Z. The one-hour offset is subtracted to obtain UTC

- One limitation of excluding malformed records:
Rejected records are excluded from the analysis even though they remain in the original CSV files. They may contain relevant activity, so the findings could be incomplete

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```
5 November 2026

Command: python3 check_solution.py

Ran 21 tests in 0.004s

OK

```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

The claim is unsupported in several respects. A005 (account analyst01, session S-104) has the largest recorded download total, but this does not establish that the account belongs to an attacker or that a person stole evidence. The logs record successful download events, not the identity of the operator, authorization status, file contents or completed exfiltration. The SHA-256 matches establish that the supplied CSV files agree byte-for-byte with the provided manifest; they do not prove the original logs are authentic or complete.

A more cautious conclusion is that session S-104 is the highest-volume session identified by the stated investigation rules and merits further review. The available records do not establish who operated the session, whether the activity was unauthorized, or whether data was exfiltrated.

One claim we corrected or independently verified, with event IDs:

We independently checked that session A005 has three qualifying successful download events (F001, F002 and F003). Their recorded byte values are 5,242,880, 262,144 and 4,096, giving a total of 5,509,120 bytes. We also checked that F004 is excluded because it occurs one second after the ten-minute follow-up window. These observations agree with summary.json and the original file_log.csv.

Final 180-220 word finding, reviewed and edited by the pair:

Final forensic finding

The investigation identified three successful sessions preceded by at least three failed login attempts within the specified five-minute window. Session S-104, associated with account analyst01 and source IP 203.0.113.44, is prioritised for review because it recorded the largest download volume. Authentication events A002, A003 and A004 preceded successful login A005 at 09:03 UTC on 20 October 2026. Three successful downloads, F001, F002 and F003, were recorded between 09:05 and 09:13 UTC, totalling 5,509,120 bytes. F004 was excluded because it occurred one second beyond the ten-minute follow-up window.

For comparison, session S-304, associated with analyst02, recorded one successful download (F013) of 2,048 bytes following failures A015, A016 and A017 and successful login A018. Session S-104 therefore merits earlier review based on recorded volume, not presumed intent.

These records do not establish the identity of the session operator or whether the downloads were authorised. Furthermore, rejected malformed records and possible gaps in log collection limit the completeness of the analysis. A plausible benign explanation is that an authorised analyst was exporting evidence as part of routine investigative work.

Further investigation should request portal audit records showing account permissions and approved export activity, and network or endpoint records establishing whether the recorded transfers reached an external destination.

The findings identify activity for review, not proof of intrusion, theft or exfiltration.


## AI use and pair review

- Names of both partners: Satya Prakash Enjeti
- Working arrangement: Completed individually because a partner was not available before the submission deadline.
- GenAI tool/ChatGPT date and displayed model: ChatGPT, 5 November 2026. Model: GPT-6
- Prompts used and what they produced:
Prompt 1: Implemented find_login_sequences to identify successful logins preceded by repeated failures.

Prompt 2: Implemented correlate_downloads to correlate successful downloads with flagged login sessions.

Prompt 3: Evaluated the overstated claim about attacker identity, theft and hash verification.

Prompt 4: Drafted the final forensic finding for review.

- One follow-up question or correction, with a short response excerpt:
Checked the A001/A002 login boundary and F003/F004 download boundary. Confirmed that A002 and F003 qualify, while A001 and F004 are outside their respective time windows.

- Results of code and evidence checks performed:
All 21 supplied tests passed. SHA-256 checks matched the supplied manifest. Generated results were compared against the original synthetic CSV records.

- Individual Review: Reviewed the function contracts, evidence IDs, timestamps, download totals and limitations of the findings independently. Pair review was not possible because I completed the exercise individually.


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
