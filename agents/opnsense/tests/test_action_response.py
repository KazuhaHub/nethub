"""Real JavaScript projection refuses private fields and unknown action states."""
from pathlib import Path
import shutil
import subprocess


def test_native_browser_failure_projection_exports_only_closed_response_fields():
    module = (Path(__file__).resolve().parents[1] / 'acceptance/action_response.mjs').as_uri()
    script = '''
import assert from 'node:assert/strict';
const { actionResponse } = await import(process.argv[1]);
for (const phase of ['applied', 'busy', 'trust_changed', 'saved', 'error']) {
  const result = actionResponse(200, { success: false, phase,
    message: 'private message', device_secret: 'private credential', url: 'https://private.invalid' });
  assert.deepEqual(result, { http_status: 200, success: false, phase });
  assert.equal(JSON.stringify(result).includes('private'), false);
}
for (const value of [null, [], 'private', { success: 'private', phase: 'private' },
  { success: 1, phase: { private: 'value' } }]) {
  assert.deepEqual(actionResponse(503, value), { http_status: 503, success: 'unknown', phase: 'unknown' });
}
assert.deepEqual(actionResponse(200, { success: true, phase: 'applied' }),
  { http_status: 200, success: true, phase: 'applied' });
for (const status of [true, 200.1, 99, 600, 'private']) {
  assert.equal(actionResponse(status, null).http_status, 0);
}
for (const reason of ['backend_response', 'backend_exception', 'trust_sync', 'trust_recovery',
  'native_model', 'rotation_journal', 'native_save', 'interrupted', 'unclassified',
  'rotation_request', 'rotation_protocol', 'rotation_response', 'rotation_binding',
  'runtime_trust', 'mutation_lock', 'inactive', 'runtime_configuration', 'runtime_template',
  'runtime_verify', 'service_action', 'service_exit', 'operation_timeout']) {
  assert.deepEqual(actionResponse(200, { success: false, phase: 'error', failure_reason: reason,
    message: 'private response', device_secret: 'private credential' }),
    { http_status: 200, success: false, phase: 'error', failure_reason: reason });
}
for (const reason of ['private', [], {}, null, true]) {
  assert.deepEqual(actionResponse(200, { success: false, phase: 'error', failure_reason: reason }),
    { http_status: 200, success: false, phase: 'error' });
}
'''
    result = subprocess.run([shutil.which('node') or 'node', '--input-type=module', '-e', script, module],
                            capture_output=True, timeout=10)
    assert result.returncode == 0, 'Native action response projection control failed'
    assert result.stdout == b'' and result.stderr == b''
