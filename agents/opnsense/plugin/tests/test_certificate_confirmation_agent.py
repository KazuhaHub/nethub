"""Confirm only verified application and retry lost replies without reinstallation."""
import copy
import json
import os
from pathlib import Path
from unittest import mock
import xml.etree.ElementTree as ET

import pytest

pytest.importorskip('fcntl', reason='Native shared-lock contracts require POSIX')

from test_lifecycle_agent import case
from test_certificate_chain import chain,DEVICE,HOST
from test_certificate_transaction import NativeModel
from certificate_chain import ChainVerifier
from certificate_key import KeyStore
from certificate_transaction import CertificateTransaction
from protocol import ProtocolError,VERSION

pytestmark=pytest.mark.skipif(os.name=='nt',reason='Native shared-lock contracts require POSIX')


@pytest.fixture
def application(case,chain):
    case.agent.config.chmod(0o700)
    directory=case.agent.config/'gui-key';directory.mkdir(mode=0o700)
    for name in ['key.pem','state.json']:
        path=directory/name;path.write_bytes((chain.key.directory/name).read_bytes());path.chmod(0o600)
    tree=ET.parse(case.root/'conf/config.xml');model=tree.find('OPNsense/NetHubAgent')
    for field,text in [('device_id',DEVICE),('subdomain',HOST.split('.')[0])]:
        node=model.find(field)
        if node is None:node=ET.SubElement(model,field)
        node.text=text
    tree.write(case.root/'conf/config.xml')
    value=chain.issue();path=case.agent.config/'gui-certificate.json';path.write_bytes(KeyStore._encoded(value));path.chmod(0o600)
    backend=NativeModel(case.agent.config/'gui-apply');transaction=CertificateTransaction(backend.directory,backend)
    return case,chain,value,path,backend,transaction


def patches(application):
    case,chain,_,_,_,transaction=application
    return (mock.patch.object(case.agent,'gui_transaction',return_value=transaction),
            mock.patch('certificate_sync.CertificateSynchronizer.sync',return_value={'phase':'verified'}),
            mock.patch('certificate_chain.ChainVerifier',side_effect=lambda key:ChainVerifier(key,chain.ca)))


def accepted(value):
    return {'agent_protocol_version':VERSION,'device_id':DEVICE,'request_id':value['request']['request_id'],
            'csr_fingerprint':value['request']['csr_fingerprint'],'generation_id':value['issued']['generation_id'],
            'generation':value['issued']['generation'],'leaf_fingerprint':value['issued']['leaf_fingerprint'],
            'accepted':True,'accepted_at':'2026-10-20T00:00:00.000000Z'}


def test_lost_confirmation_retries_same_verified_journal_without_reinstalling(application):
    case,_,value,_,backend,transaction=application
    initial=case.agent.live.read_bytes();key=(case.agent.config/'gui-key/key.pem').read_bytes();calls=[]
    def network(origin,path,body,**kwargs):
        assert transaction._read()['phase']=='applied' and backend.events[-1] in ('check','probe')
        calls.append(body)
        if len(calls)==1:raise ProtocolError('private lost reply detail')
        return accepted(value)
    p1,p2,p3=patches(application)
    with p1,p2,p3,mock.patch('certificate_protocol.request_json',side_effect=network):
        first=case.agent.apply('certificate');second=case.agent.apply('certificate')
    assert first['phase']=='applied_unconfirmed' and first['confirmed'] is False and 'private' not in json.dumps(first)
    assert second['phase']=='applied' and second['confirmed'] is True
    assert calls[0]==calls[1] and backend.events.count('install')==1 and backend.events.count('rollback')==0
    assert case.agent.live.read_bytes()==initial and (case.agent.config/'gui-key/key.pem').read_bytes()==key
    assert case.active and not case.mutations()


def test_server_minor_upgrade_only_enables_reporting_and_keeps_the_applied_generation(application):
    case,_,value,path,backend,transaction=application
    value['agent_protocol_version']='1.3.0';path.write_bytes(KeyStore._encoded(value))
    p1,p2,p3=patches(application)
    with p1,p2,p3,mock.patch('certificate_protocol.request_json',return_value=accepted(value)) as network:
        first=case.agent.apply('certificate');before=transaction._read()['nonce'];network.assert_not_called()
        value['agent_protocol_version']=VERSION;path.write_bytes(KeyStore._encoded(value))
        second=case.agent.apply('certificate')
    assert first['phase']=='applied_unconfirmed' and 'upgrade' in first['message']
    assert second['confirmed'] and transaction._read()['nonce']==before and backend.events.count('install')==1
    assert network.call_count==1 and case.active and not case.mutations()


def test_failed_probe_and_delayed_retry_never_report_application(application):
    case,_,_,_,backend,_=application;backend.healthy=False
    p1,p2,p3=patches(application)
    with p1,p2,p3,mock.patch('certificate_protocol.request_json') as network:
        first=case.agent.apply('certificate');second=case.agent.apply('certificate')
    assert first['phase']=='error' and second['phase']=='retry_wait'
    assert backend.events.count('rollback')==1 and backend.native['ref']=='original'
    network.assert_not_called();assert case.active and not case.mutations()


def test_untrusted_changed_material_never_reaches_native_apply_or_confirmation(application):
    case,_,value,path,backend,_=application
    value['assigned_host']='ijklmnop.devices.example.test';path.write_bytes(KeyStore._encoded(value))
    p1,p2,p3=patches(application)
    with p1,p2,p3,mock.patch('certificate_protocol.request_json') as network:
        result=case.agent.apply('certificate')
    assert result['phase']=='error' and not backend.events
    network.assert_not_called();assert case.active and not case.mutations()
