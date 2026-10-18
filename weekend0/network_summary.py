"""Validate a complete sanitized W0 network sample and calculate Q2 metrics."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import io
import json
import math
from pathlib import Path
import re
import statistics

FIELDS = {
    'Network', 'Round', 'Port', 'StartedUtc', 'CurlExit', 'HttpCode',
    'TcpConnected', 'TimeConnect', 'TimeAppConnect', 'TimeTotal', 'AddressFamily',
}


class InvalidSample(ValueError):
    """The supplied sample cannot support a W0 network comparison."""


def summarize(data: bytes) -> dict:
    if len(data) > 128 * 1024:
        raise InvalidSample('Sample exceeds the expected size.')
    try:
        reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig'), newline=''))
        if reader.fieldnames is None or len(reader.fieldnames) != len(FIELDS) or set(reader.fieldnames) != FIELDS:
            raise InvalidSample('Use the sanitized CSV with exactly the expected columns.')
        rows = list(reader)
    except (UnicodeError, csv.Error) as error:
        raise InvalidSample('Sample is not a valid UTF-8 CSV.') from error
    if len(rows) != 40:
        raise InvalidSample('Require exactly 20 alternating pairs, with 40 rows total.')
    expected = [(round_number, port) for round_number in range(1, 21) for port in (443, 8443)]
    parsed = []
    labels = set()
    previous = None
    for row, pair in zip(rows, expected):
        try:
            if None in row or any(value is None for value in row.values()):
                raise ValueError
            label = row['Network']
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', label):
                raise ValueError
            labels.add(label)
            if (int(row['Round']), int(row['Port'])) != pair or row['AddressFamily'] != 'IPv4':
                raise ValueError
            stamp = datetime.fromisoformat(row['StartedUtc'].replace('Z', '+00:00'))
            if stamp.utcoffset() is None or (previous is not None and stamp < previous):
                raise ValueError
            previous = stamp
            exit_code = int(row['CurlExit'])
            if not 0 <= exit_code <= 255 or not re.fullmatch(r'(?:000|[1-5][0-9]{2})', row['HttpCode']):
                raise ValueError
            values = [float(row[name]) for name in ('TimeConnect', 'TimeAppConnect', 'TimeTotal')]
            if any(not math.isfinite(value) or value < 0 for value in values):
                raise ValueError
            connect, app_connect, total = values
            if connect > total + 1e-6 or (app_connect > 0 and (app_connect + 1e-6 < connect or app_connect > total + 1e-6)):
                raise ValueError
            if row['TcpConnected'].lower() not in ('true', 'false'):
                raise ValueError
            connected = row['TcpConnected'].lower() == 'true'
            if connected != (connect > 0) or (app_connect > 0 and not connected):
                raise ValueError
            parsed.append({'round': pair[0], 'port': pair[1], 'connected': connected,
                           'connect': connect, 'app_connect': app_connect, 'total': total,
                           'curl_exit': exit_code})
        except (ValueError, TypeError, KeyError) as error:
            raise InvalidSample('A row has invalid ordering, metadata, timing, or TCP status.') from error
    if len(labels) != 1:
        raise InvalidSample('Keep one network label throughout a sample.')

    def median(values):
        return statistics.median(values) if values else None

    ports = {}
    for port in (443, 8443):
        samples = [row for row in parsed if row['port'] == port]
        tcp = [row for row in samples if row['connected']]
        tls = [row for row in tcp if row['app_connect'] > 0]
        ports[str(port)] = {
            'samples': 20, 'tcp_successes': len(tcp), 'tcp_success_percent': 5 * len(tcp),
            'tls_completed': len(tls), 'curl_successes': sum(row['curl_exit'] == 0 for row in samples),
            'tcp_median_seconds': median([row['connect'] for row in tcp]),
            'tcp_range_seconds': [min(row['connect'] for row in tcp), max(row['connect'] for row in tcp)] if tcp else None,
            'tls_completion_median_seconds': median([row['app_connect'] for row in tls]),
            'tls_completion_range_seconds': [min(row['app_connect'] for row in tls), max(row['app_connect'] for row in tls)] if tls else None,
            'tls_handshake_median_seconds': median([row['app_connect'] - row['connect'] for row in tls]),
            'failed_rounds': [row['round'] for row in samples if not row['connected']],
            'first_ten_tcp_successes': sum(row['connected'] for row in samples[:10]),
            'last_ten_tcp_successes': sum(row['connected'] for row in samples[10:]),
        }
    baseline, tunnel = (ports[str(port)]['tcp_successes'] for port in (443, 8443))
    return {
        'network': next(iter(labels)), 'sample_sha256': hashlib.sha256(data).hexdigest(),
        'complete_alternating_sample': True, 'ports': ports,
        'difference_percentage_points': 5 * (baseline - tunnel),
        'q2_triggered': baseline - tunnel >= 4 or tunnel == 0,
        'both_ports_zero': baseline == 0 and tunnel == 0,
        'external_network_provenance_verified': False,
        'experiment_4_accepted': False,
        'review_required': 'Confirm the external network and relay availability for this window; assess each network separately.',
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', type=Path, help='A completed *.sanitized.csv file')
    args = parser.parse_args()
    try:
        result = summarize(args.sample.read_bytes())
    except (InvalidSample, OSError) as error:
        message = str(error) if isinstance(error, InvalidSample) else 'Cannot read sample file.'
        parser.exit(2, message + '\n')
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
