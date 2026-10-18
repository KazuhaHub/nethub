"""Stage the relay binary using the same official release lock as the agent."""
from pathlib import Path
import sys

PLUGIN = Path(__file__).resolve().parents[2] / 'agents/opnsense/plugin'
sys.path.insert(0, str(PLUGIN))
from frp_artifact import fetch, read_lock


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python3 deploy/frp/fetch.py OUTPUT')
    if (Path(__file__).parent / 'FRP_VERSION').read_text().strip() != read_lock()['version']:
        raise SystemExit('Relay and agent frp versions differ')
    fetch('linux_amd64', 'frps', Path(sys.argv[1]))
