// Public diagnostics contain only HTTP status and closed native action states.
export function actionResponse(status, value) {
  const phases = ['applied', 'busy', 'trust_changed', 'saved', 'error'];
  return {
    http_status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : 0,
    success: value?.success === true || value?.success === false ? value.success : 'unknown',
    phase: phases.includes(value?.phase) ? value.phase : 'unknown',
  };
}
