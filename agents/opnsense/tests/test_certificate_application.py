"""Report only exact verified generation identity and correlate server acceptance."""
import copy
import json
from pathlib import Path
import sys
from unittest import mock

import pytest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'agents/opnsense/plugin/src/usr/local/opnsense/scripts/nethub-agent'))
import certificate_protocol as CLIENT
from protocol import ProtocolError,VERSION


def example(name):
    return json.loads((ROOT/'proto/examples/valid'/(name+'.json')).read_text())


def test_application_report_sends_only_public_pins_and_strips_optional_response_fields():
    delivered=example('certificate-issued-response')
    expected=example('certificate-applied-request');expected['agent_protocol_version']=VERSION
    reply=example('certificate-applied-response');reply['future_optional']={'ignored':True}
    with mock.patch.object(CLIENT,'request_json',return_value=reply) as request:
        actual=CLIENT.report_applied('https://console.example.test','not-forwarded-in-body',delivered['device_id'],delivered['request'],delivered['issued'])
    assert actual==example('certificate-applied-response')
    assert request.call_args.args[1]=='/api/v1/devices/gui-certificate/applied' and request.call_args.args[2]==expected
    assert request.call_args.kwargs['secret']=='not-forwarded-in-body'
    assert 'chain_pem' not in expected and 'csr_der' not in expected


@pytest.mark.parametrize('field,value',[('device_id','00000000-0000-0000-0000-000000000000'),('request_id','00000000-0000-0000-0000-000000000000'),('csr_fingerprint','0'*64),('generation_id','00000000-0000-0000-0000-000000000000'),('generation',2),('generation',True),('leaf_fingerprint','0'*64),('accepted',False),('accepted',1),('accepted_at','2026-10-20T00:00:00Z'),('agent_protocol_version','1.3.0'),('agent_protocol_version','2.0.0')])
def test_response_cannot_acknowledge_another_report_or_unsupported_peer(field,value):
    reply=example('certificate-applied-response');reply[field]=value
    with pytest.raises(ProtocolError):CLIENT.application_response(reply,example('certificate-applied-request'))


@pytest.mark.parametrize('changes',[{'generation':0},{'generation':True},{'generation':2147483648},{'generation_id':'not-an-id'},{'leaf_fingerprint':'A'*64}])
def test_invalid_local_material_never_enters_transport(changes):
    delivered=example('certificate-issued-response');issued=dict(delivered['issued'],**changes)
    with mock.patch.object(CLIENT,'request_json') as request:
        with pytest.raises(ProtocolError):CLIENT.report_applied('https://console.example.test','not-sent',delivered['device_id'],delivered['request'],issued)
    request.assert_not_called()


def test_required_application_response_fields_are_not_optional():
    expected=example('certificate-applied-request')
    for field in example('certificate-applied-response'):
        reply=example('certificate-applied-response');del reply[field]
        with pytest.raises(ProtocolError):CLIENT.application_response(reply,expected)
    reply=example('certificate-applied-response')
    for i in range(17):reply['extra'+str(i)]=True
    with pytest.raises(ProtocolError):CLIENT.application_response(reply,expected)


@pytest.mark.parametrize('version,expected',[('1.3.99',False),('1.4.0',True),('1.40.0-rc.1',True),('1.9999999999999999999999.0',True),('2.0.0',False),('1.04.0',False),(None,False)])
def test_application_capability_uses_bounded_semver(version,expected):
    assert CLIENT.supports_application_reports(version) is expected
