"""Check the plugin source contract before building on the target appliance."""
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]
MVC = ROOT / 'src/usr/local/opnsense/mvc/app'
MODEL = MVC / 'models/OPNsense/NetHubAgent/NetHubAgent.xml'


@pytest.mark.parametrize('path', sorted((ROOT / 'src').rglob('*.xml')), ids=lambda p: p.name)
def test_xml_is_well_formed(path):
    ET.parse(path)


def test_model_mount_and_safe_defaults():
    model = ET.parse(MODEL).getroot()
    assert model.findtext('mount') == '//OPNsense/NetHubAgent'
    fields = model.find('items')
    assert {item.tag for item in fields} == {
        'enabled', 'server_addr', 'server_port', 'subdomain', 'device_id',
        'device_secret', 'frp_token', 'domain_claim', 'cluster_hint',
    }
    assert fields.findtext('enabled/Default') == '0'
    assert fields.findtext('cluster_hint/Default') == '0'
    assert fields.findtext('server_port/MinimumValue') == '1'
    assert fields.findtext('server_port/MaximumValue') == '65535'


def test_only_enabled_is_exposed_in_the_form():
    form = ET.parse(MVC / 'controllers/OPNsense/NetHubAgent/forms/settings.xml')
    assert [field.findtext('id') for field in form.findall('field')] == ['nethubagent.enabled']


def test_version_and_package_identity_agree():
    product = json.loads((ROOT / 'src/usr/local/opnsense/version/nethub-agent').read_text())
    version = re.search(r'^VERSION=(\S+)$', (ROOT / 'build.sh').read_text(), re.M)[1]
    assert product['product_version'] == version == ET.parse(MODEL).findtext('version')
    manifest = json.loads((ROOT / 'packaging/freebsd/+MANIFEST.in').read_text())
    assert product['product_id'] == manifest['name'] == 'os-nethub-agent'
    assert product['product_email'] == manifest['maintainer'] == 'admin@kazuha.org'
    assert product['product_website'] == manifest['www']


@pytest.mark.parametrize('path', sorted((ROOT / 'src').rglob('*.php')), ids=lambda p: p.name)
def test_php_syntax(path):
    subprocess.run(['php', '-l', str(path)], check=True, capture_output=True)


@pytest.mark.parametrize('path', [ROOT / 'build.sh', *sorted((ROOT / 'packaging/freebsd').glob('+*INSTALL'))])
def test_shell_syntax(path):
    subprocess.run(['sh', '-n', str(path)], check=True, capture_output=True)


@pytest.mark.parametrize('payload', ['a"b', "a'b", 'a\nb', 'a\rb', 'a\\b', 'a\nb\n'])
def test_text_masks_reject_config_injection(payload):
    fields = ET.parse(MODEL).find('items')
    masks = [field.findtext('mask') for field in fields if field.get('type') == 'TextField']
    program = '$v=json_decode(stream_get_contents(STDIN),true);foreach($v["masks"] as $m){if(preg_match($m,$v["payload"])!==0){exit(1);}}'
    subprocess.run(['php', '-r', program], input=json.dumps({'masks': masks, 'payload': payload}), text=True, check=True, capture_output=True)


def test_expected_values_pass_text_masks():
    fields = ET.parse(MODEL).find('items')
    examples = {'server_addr': 'relay.example.com', 'subdomain': 'device-abc', 'device_id': 'device_123', 'device_secret': 'abc/+def==', 'frp_token': 'abc-_def', 'domain_claim': 'header.payload.signature'}
    pairs = [(fields.findtext(name + '/mask'), value) for name, value in examples.items()]
    program = '$v=json_decode(stream_get_contents(STDIN),true);foreach($v as [$m,$s]){if(preg_match($m,$s)!==1){exit(1);}}'
    subprocess.run(['php', '-r', program], input=json.dumps(pairs), text=True, check=True, capture_output=True)


def test_settings_api_does_not_expose_or_accept_credentials():
    controller = MVC / 'controllers/OPNsense/NetHubAgent/Api/SettingsController.php'
    cases = [
        {'post': True, 'settings': {'enabled': value}, 'allowed': True}
        for value in ['0', '1']
    ] + [
        {'post': True, 'settings': value, 'allowed': False}
        for value in [None, [], {}, {'device_secret': 'replacement'},
                      {'enabled': '1', 'frp_token': 'replacement'},
                      {'enabled': ['1']}, {'enabled': 'yes'}]
    ] + [{'post': False, 'settings': {'enabled': '1'}, 'allowed': False}]
    subprocess.run(['php', '-n', str(ROOT / 'tests/settings_contract.php'), str(controller)], input=json.dumps(cases), text=True, check=True, capture_output=True)
