"""Wait for the exact PR source's ordinary CI before allocating a native guest."""
import json
import os
from pathlib import Path
import re
import sys
import time

from guest import GuestError, invoke
from with_images import validate_run


def main():
    head = os.environ.get('NETHUB_SOURCE_HEAD', '')
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or not re.fullmatch(r'[a-f0-9]{40}', head)):
        raise GuestError('Exact hosted PR source required')
    deadline = time.monotonic() + 32 * 60
    selected = None
    while time.monotonic() < deadline:
        if selected is None:
            runs = json.loads(invoke(['gh', 'run', 'list', '--repo', 'KazuhaHub/nethub', '--workflow', 'ci.yml',
                                      '--commit', head, '--event', 'pull_request', '--limit', '5',
                                      '--json', 'databaseId'], 'source CI inventory'))
            if runs:
                selected = str(runs[0]['databaseId'])
        if selected is not None:
            run = json.loads(invoke(['gh', 'api', 'repos/KazuhaHub/nethub/actions/runs/' + selected], 'source CI progress'))
            if run['status'] == 'completed':
                jobs = json.loads(invoke(['gh', 'run', 'view', selected, '--repo', 'KazuhaHub/nethub',
                                          '--json', 'jobs'], 'source CI outcomes'))['jobs']
                validate_run(run, jobs, head)
                with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8') as output:
                    output.write('run=' + selected + '\n')
                print('Exact-source six-job CI accepted for installed native execution')
                return
        time.sleep(15)
    raise GuestError('Exact-source CI did not finish within the image gate deadline')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Native image gate failed: ' + (str(error) if isinstance(error, GuestError) else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
