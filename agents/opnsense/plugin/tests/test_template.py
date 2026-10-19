"""Check the actual template's TLS, heartbeat, and proxy structure."""
from pathlib import Path
import tomllib

import jinja2
import pytest

TEMPLATE = Path(__file__).resolve().parents[1] / 'src/usr/local/opnsense/service/templates/OPNsense/NetHubAgent/frpc.toml.j2'


@pytest.mark.parametrize('port,expected', [('', 443), ('9443', 9443)])
@pytest.mark.parametrize('device_id', [
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
])
def test_enabled_template(port, expected, device_id):
    context = {'OPNsense': {'NetHubAgent': {
        'enabled': '1', 'server_addr': 'relay.example.com', 'server_port': '7000',
        'frp_token': 'test-only', 'device_id': device_id,
        'domain_claim': 'test.claim', 'subdomain': 'abcd1234'}},
        'system': {'webgui': {'port': port}}}
    text = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(TEMPLATE.read_text()).render(**context)
    config = tomllib.loads(text)
    assert config['loginFailExit'] is False
    assert config['transport']['heartbeatInterval'] == 10
    assert config['transport']['heartbeatTimeout'] == 30
    assert config['transport']['tls'] == {
        'enable': True, 'trustedCaFile': '/usr/local/etc/nethub-agent/relay-ca.pem',
        'serverName': 'relay.example.com'}
    assert config['metadatas']['device_id'] == device_id
    assert config['proxies'] == [{'name': f'nethub-{device_id}-web', 'type': 'https',
                                  'localIP': '127.0.0.1', 'localPort': expected,
                                  'subdomain': 'abcd1234'}]
    assert 'webServer' not in config
    assert 'customDomains' not in text


def test_disabled_template_requires_no_credentials():
    text = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(TEMPLATE.read_text()).render(
        OPNsense={'NetHubAgent': {'enabled': '0'}})
    assert tomllib.loads(text) == {}
