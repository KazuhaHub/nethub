"""Validate shared wire examples and the installed agent's request builder."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[3]
PROTO = ROOT / 'proto'
SOURCE = ROOT / 'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent/protocol.py'
SPEC = importlib.util.spec_from_file_location('nethub_wire_protocol', SOURCE)
AGENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AGENT)
SCHEMAS = {p.name: json.loads(p.read_text(encoding='utf-8')) for p in (PROTO / 'v1').glob('*.schema.json')}
REGISTRY = Registry().with_resources((s['$id'], Resource.from_contents(s)) for s in SCHEMAS.values())
MANIFEST = json.loads((PROTO / 'examples/manifest.json').read_text(encoding='utf-8'))


def validator(name):
    return Draft202012Validator(SCHEMAS[name], registry=REGISTRY, format_checker=FormatChecker())


@pytest.mark.parametrize('entry', MANIFEST, ids=lambda e: e['path'])
def test_shared_example(entry):
    value = json.loads((PROTO / 'examples' / entry['path']).read_text(encoding='utf-8'))
    assert validator(entry['schema']).is_valid(value) == entry['valid']


def test_schema_definitions_and_manifest_coverage():
    for schema in SCHEMAS.values():
        Draft202012Validator.check_schema(schema)
    listed = {entry['schema'] for entry in MANIFEST if entry['valid']}
    assert listed == set(SCHEMAS) - {'common.schema.json'}
    files = {str(p.relative_to(PROTO / 'examples')).replace('\\', '/') for kind in ['valid', 'invalid'] for p in (PROTO / 'examples' / kind).glob('*.json')}
    assert files == {entry['path'] for entry in MANIFEST}


def test_actual_agent_request_matches_shared_schema():
    expected = json.loads((PROTO / 'examples/valid/enroll-request.json').read_text(encoding='utf-8'))
    expected['agent_protocol_version'] = AGENT.VERSION
    actual = AGENT.build_enroll_request(expected['enroll_token'], expected['platform_version'],
                                      expected['agent_version'], expected['hostname'])
    assert actual == expected
    validator('enroll-request.schema.json').validate(actual)
    assert AGENT.VERSION == (PROTO / 'VERSION').read_text(encoding='utf-8').strip()


@pytest.mark.parametrize('changes', [
    {'token': 'A' * 42 + 'B'}, {'token': 'A' * 43 + '='},
    {'token': 'private-input-not-a-token'}, {'hostname': 'router.example.com\nvalue=true'},
    {'agent_version': 'x' * 129}, {'platform_version': 'version\x7f'},
    {'cluster_hint': 1}, {'hostname': 'a' * 64 + '.example.com'},
])
def test_request_builder_rejects_invalid_inputs_without_echoing_them(changes):
    args = dict(token='A' * 43, platform_version='26.7.7', agent_version='0.0.2', hostname='router.example.com')
    args.update(changes)
    with pytest.raises(AGENT.ProtocolError, match='^Invalid enrollment input$'):
        AGENT.build_enroll_request(**args)


def test_future_platforms_and_optional_extensions_do_not_require_a_schema_rewrite():
    sample = json.loads((PROTO / 'examples/valid/enroll-request.json').read_text(encoding='utf-8'))
    for platform in ['openwrt', 'vyos', 'future-router']:
        value = copy.deepcopy(sample)
        value.update(platform=platform, agent_protocol_version='1.2.0', future_optional={'hint': True})
        validator('enroll-request.schema.json').validate(value)


def test_required_fields_and_claim_fields_remain_strict():
    for name in SCHEMAS.keys() - {'common.schema.json'}:
        example = json.loads((PROTO / 'examples/valid' / name.replace('.schema.json', '.json')).read_text(encoding='utf-8'))
        for field in SCHEMAS[name]['required']:
            changed = dict(example)
            del changed[field]
            assert not validator(name).is_valid(changed), (name, field)
    claim = json.loads((PROTO / 'examples/valid/domain-claim.json').read_text(encoding='utf-8'))
    claim['future_optional'] = True
    assert not validator('domain-claim.schema.json').is_valid(claim)


def test_overlapping_ca_bundle_has_a_bounded_shape():
    response = json.loads((PROTO / 'examples/valid/enroll-response.json').read_text(encoding='utf-8'))
    response['relay_ca_pem'] *= 2
    validator('enroll-response.schema.json').validate(response)
    response['relay_ca_pem'] += response['relay_ca_pem']
    assert not validator('enroll-response.schema.json').is_valid(response)
