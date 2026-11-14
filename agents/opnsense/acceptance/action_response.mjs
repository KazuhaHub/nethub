// Public diagnostics contain only HTTP status and closed native action states.
export function actionResponse(status, value) {
  const phases = ['applied', 'busy', 'trust_changed', 'saved', 'error'];
  const result = {
    http_status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : 0,
    success: value?.success === true || value?.success === false ? value.success : 'unknown',
    phase: phases.includes(value?.phase) ? value.phase : 'unknown',
  };
  const reasons = ['backend_response', 'backend_exception', 'trust_sync', 'trust_recovery',
    'native_model', 'rotation_journal', 'native_save', 'interrupted', 'unclassified',
    'rotation_request', 'rotation_protocol', 'rotation_response', 'rotation_binding',
    'runtime_trust', 'mutation_lock', 'inactive', 'runtime_configuration',
    'runtime_template', 'runtime_verify', 'service_action', 'service_exit', 'operation_timeout'];
  if (result.success === false && result.phase === 'error' && reasons.includes(value?.failure_reason)) {
    result.failure_reason = value.failure_reason;
  }
  return result;
}
