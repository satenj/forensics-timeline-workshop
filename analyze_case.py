"""DF-017 synthetic investigation. Implement only the two TODO functions."""
import argparse
from datetime import timedelta
from pathlib import Path
from evidence_tools import load_case, write_json

BASE = Path(__file__).resolve().parent

def find_login_sequences(rows, min_failures=3, window_minutes=5):
    """Find successes preceded by repeated failures; return a list of dicts.

    Input: validated auth dictionaries in arbitrary order. timestamp is an
    aware UTC datetime. Group on (username, source_ip, host), all case-sensitive.
    For EACH SUCCESS at time T, select FAIL rows from that same group where
    T - timedelta(minutes=window_minutes) <= failure time < T.
    If there are at least min_failures, emit exactly one dict with these keys:
      username, source_ip, host, session_id (copied from the success),
      success_id (success event_id), success_time (success timestamp),
      failure_ids (list ordered by timestamp then event_id).
    Sort the output by (success_time, success_id). Emit nothing below threshold.
    Do not reset at earlier successes: this rule evaluates each success window
    independently. A failure may support more than one window.
    Empty input returns []. Do not mutate input. No hardcoded IDs or outcomes.
    Parameters are positive numbers. Use loops, dictionaries, lists, sorted,
    and the imported timedelta. No additional packages are needed.
    """
    
    # Group failed login events by username, source IP and host.
    failures_by_group = {}

    for row in rows:
        if row['result'] == 'FAIL':
            key = (row['username'], row['source_ip'], row['host'])

            if key not in failures_by_group:
                failures_by_group[key] = []

            failures_by_group[key].append(row)

    alerts = []

    # Evaluate every successful login independently.
    for success in rows:
        if success['result'] != 'SUCCESS':
            continue

        key = (
            success['username'],
            success['source_ip'],
            success['host']
        )

        success_time = success['timestamp']
        window_start = success_time - timedelta(minutes=window_minutes)

        matching_failures = []

        for failure in failures_by_group.get(key, []):
            if window_start <= failure['timestamp'] < success_time:
                matching_failures.append(failure)

        # Create an alert when the threshold is reached.
        if len(matching_failures) >= min_failures:
            matching_failures.sort(
                key=lambda row: (row['timestamp'], row['event_id'])
            )

            alerts.append({
                'username': success['username'],
                'source_ip': success['source_ip'],
                'host': success['host'],
                'session_id': success['session_id'],
                'success_id': success['event_id'],
                'success_time': success_time,
                'failure_ids': [
                    failure['event_id']
                    for failure in matching_failures
                ]
            })

    alerts.sort(
        key=lambda alert: (
            alert['success_time'],
            alert['success_id']
        )
    )

    return alerts


def correlate_downloads(alerts, file_rows, followup_minutes=10):
    """Enrich each alert with file activity; return a new list of new dicts.

    Input timestamps are aware UTC datetime objects; bytes is already an int.
    For each alert at success_time T, match file rows on ALL of
    (username, host, session_id). Keep only action == 'DOWNLOAD',
    result == 'SUCCESS', and T <= timestamp <= T + timedelta(minutes=followup_minutes).
    Sort matching rows by (timestamp, event_id). Copy the original alert fields
    into a NEW dict, then add:
      download_ids: matching event IDs in that order
      download_count: number of matching events (not distinct paths)
      total_bytes: sum of the matching bytes values
    Keep alerts with no matches: [], 0, 0. Sort returned alerts by descending
    total_bytes, then success_time, then success_id. Empty alerts returns [].
    Do not mutate either input or its nested lists. Do not merge sessions based
    only on a shared account. No hardcoded IDs or outcomes; no extra packages.
    """
    # TODO 2: replace this raise with your implementation.
    
    findings = []

    for alert in alerts:
        success_time = alert['success_time']
        window_end = success_time + timedelta(minutes=followup_minutes)

        matching_downloads = []

        for row in file_rows:
            if (
                row['username'] == alert['username']
                and row['host'] == alert['host']
                and row['session_id'] == alert['session_id']
                and row['action'] == 'DOWNLOAD'
                and row['result'] == 'SUCCESS'
                and success_time <= row['timestamp'] <= window_end
            ):
                matching_downloads.append(row)

        # Sort downloads chronologically.
        matching_downloads.sort(
            key=lambda row: (row['timestamp'], row['event_id'])
        )

        # Copy the original alert and enrich it with download information.
        result = dict(alert)

        result['download_ids'] = [
            row['event_id'] for row in matching_downloads
        ]

        result['download_count'] = len(matching_downloads)

        result['total_bytes'] = sum(
            row['bytes'] for row in matching_downloads
        )

        findings.append(result)

    # Rank by descending bytes, then success time and success ID.
    findings.sort(
        key=lambda item: (
            -item['total_bytes'],
            item['success_time'],
            item['success_id']
        )
    )

    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['logins', 'all'], default='all')
    args = parser.parse_args()
    try:
        auth, files, audit = load_case(BASE)
    except ValueError as error:
        parser.exit(1, f'Evidence check failed: {error}\n')
    write_json(BASE / 'audit.json', audit)
    print('SHA-256 checks match the supplied manifest.')
    for name in ['auth_log.csv', 'file_log.csv']:
        info = audit[name]
        print(f"{name}: {info['data_rows']} rows; {info['accepted']} accepted; "
              f"{len(info['duplicates'])} duplicate; {len(info['rejected'])} rejected.")
    print('Saved audit.json. A hash match does not prove origin or completeness.')
    try:
        alerts = find_login_sequences(auth)
        write_json(BASE / 'login_alerts.json', alerts)
        print(f'Found {len(alerts)} login sequences; saved login_alerts.json.')
        if args.stage == 'logins':
            return
        findings = correlate_downloads(alerts, files)
    except NotImplementedError as error:
        print(f'Starter ready: {error}. Previously generated outputs may be stale.')
        return
    summary = {'case': 'DF-017 training data only',
               'rule': {'min_failures': 3, 'login_window_minutes': 5, 'followup_minutes': 10},
               'evidence_sha256': audit['sha256'], 'findings': findings,
               'interpretation': 'Rule matches identify sessions for review; they do not prove intrusion, exfiltration, or identity.'}
    write_json(BASE / 'summary.json', summary)
    print('Saved summary.json. Verify event IDs against both original CSV files.')
    for item in findings:
        print(f"{item['success_id']} {item['username']} {item['session_id']}: "
              f"{len(item['failure_ids'])} failures, {item['download_count']} downloads, "
              f"{item['total_bytes']} bytes")

if __name__ == '__main__':
    main()
