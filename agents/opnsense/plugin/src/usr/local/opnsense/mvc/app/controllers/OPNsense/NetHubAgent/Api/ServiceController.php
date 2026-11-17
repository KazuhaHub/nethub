<?php

namespace OPNsense\NetHubAgent\Api;

class ServiceController extends \OPNsense\Base\ApiControllerBase
{
    private function invoke($action)
    {
        if ($action !== 'status') {
            $this->throwReadOnly();
        }
        $backend = new \OPNsense\Core\Backend();
        $response = in_array($action, ['disable', 'enable'], true) ?
            $backend->configdRun('nethub-agent ' . $action, false, 40) :
            $backend->configdRun('nethub-agent ' . $action);
        $result = json_decode($response, true);
        return is_array($result) ? $result : ['success' => false, 'message' => gettext('Service response unavailable.')];
    }

    public function statusAction()
    {
        return $this->invoke('status');
    }

    public function reconcileAction()
    {
        return $this->request->isPost() ? $this->invoke('reconcile') : ['success' => false];
    }

    public function reportAction()
    {
        return $this->request->isPost() ? $this->invoke('report') : ['success' => false];
    }

    public function startAction()
    {
        return $this->request->isPost() ? $this->invoke('start') : ['success' => false];
    }

    public function stopAction()
    {
        return $this->request->isPost() ? $this->invoke('stop') : ['success' => false];
    }

    public function restartAction()
    {
        return $this->request->isPost() ? $this->invoke('restart') : ['success' => false];
    }

    public function disableAction()
    {
        return $this->request->isPost() ? $this->invoke('disable') : ['success' => false];
    }

    public function enableAction()
    {
        return $this->request->isPost() ? $this->invoke('enable') : ['success' => false];
    }

    public function rotateAction()
    {
        if (!$this->request->isPost()) { return ['success' => false]; }
        $this->throwReadOnly();
        $failure = ['success' => false, 'action' => 'rotate', 'phase' => 'error',
            'failure_reason' => 'backend_response',
            'message' => gettext('Rotation response unavailable. Retain local recovery state and retry.')];
        try {
            $backend = new \OPNsense\Core\Backend();
            $raw = $backend->configdRun('nethub-agent rotate', false, 100);
            if (!is_string($raw) || strlen($raw) > 4096) { return $failure; }
            $value = json_decode($raw, true, 8);
            if (!is_array($value) || !is_bool($value['success'] ?? null)) { return $failure; }
            if (($value['action'] ?? null) === 'busy' && $value['success'] === false) {
                return ['success' => false, 'action' => 'rotate', 'phase' => 'busy',
                    'message' => gettext('Another service operation is running. Retry rotation shortly.')];
            }
            if (($value['action'] ?? null) !== 'rotate') { return $failure; }
            if ($value['success'] === true && ($value['phase'] ?? null) === 'applied') {
                return ['success' => true, 'action' => 'rotate', 'phase' => 'applied',
                    'message' => gettext('Credentials rotated. Local access policy retained.')];
            }
            if ($value['success'] === false && ($value['phase'] ?? null) === 'trust_changed') {
                return ['success' => false, 'action' => 'rotate', 'phase' => 'trust_changed',
                    'message' => gettext('Relay trust changed. Allow trust synchronization to finish, then retry rotation.')];
            }
            if ($value['success'] === false && ($value['phase'] ?? null) === 'saved') {
                return ['success' => false, 'action' => 'rotate', 'phase' => 'saved',
                    'message' => gettext('Credentials saved. Retry rotation to finish tunnel reconciliation.')];
            }
            if ($value['success'] === false && ($value['phase'] ?? null) === 'error') {
                // Match fixed local diagnostics; never return backend message text.
                $reasons = [
                    'Relay trust synchronization failed; inspect trust and recovery status' => 'trust_sync',
                    'Pending relay trust recovery failed; tunnel startup is blocked' => 'trust_recovery',
                    'Managed trust needs local review; retain the rotation journal' => 'trust_recovery',
                    'Native rotation model operation failed' => 'native_model',
                    'Rotation storage or original assignment needs local review' => 'rotation_journal',
                    'Native rotation model save is unconfirmed' => 'native_save',
                    'Native rotation save is unconfirmed; retain the journal' => 'native_save',
                    'Rotation interrupted; retain the private journal and retry.' => 'interrupted',
                    'Rotation response unavailable; retain the journal and retry' => 'rotation_request',
                    'Console does not support recoverable rotation' => 'rotation_protocol',
                    'Rotation response did not confirm the saved operation' => 'rotation_response',
                    'Rotation response changed the original device binding' => 'rotation_response',
                    'Pending rotation has no native model binding; local review required' => 'rotation_binding',
                    'Native settings changed during rotation; retain the journal for review' => 'rotation_binding',
                    'Invalid native rotation snapshot' => 'rotation_binding',
                    'Invalid native rotation trust' => 'runtime_trust',
                    'Update relay trust before completing credential rotation' => 'runtime_trust',
                    'Stored relay trust is invalid' => 'runtime_trust',
                    'Relay trust path is invalid' => 'runtime_trust',
                    'Stored relay trust differs; review local trust before applying' => 'runtime_trust',
                    'Private mutation lock needs local review' => 'mutation_lock',
                    'Private mutation lock changed; local review is required' => 'mutation_lock',
                    'Rotation recovery changed; retain its journal' => 'rotation_journal',
                    'Pending rotation needs local review; retain its journal' => 'rotation_journal',
                    'Rotation is unavailable after revocation or during removal' => 'inactive',
                    'Enrollment configuration is unavailable' => 'native_model',
                    'Relay certificate verification is required' => 'runtime_configuration',
                    'Install the relay CA before enabling the tunnel' => 'runtime_configuration',
                    'Relay authentication is missing' => 'runtime_configuration',
                    'Device subdomain is missing or invalid' => 'runtime_configuration',
                    'Recovery state is invalid; operator review is required' => 'runtime_configuration',
                    'Template rendering failed; live configuration was retained' => 'runtime_template',
                    'frpc rejected the candidate configuration; live configuration was retained' => 'runtime_verify',
                    'Tunnel service action failed' => 'service_action',
                    'Could not stop the tunnel' => 'service_action',
                    'Could not stop the tunnel for trust recovery' => 'service_action',
                    'Tunnel process did not remain running' => 'service_exit',
                    'Device operation timed out; inspect status before retrying' => 'operation_timeout',
                ];
                $message = $value['message'] ?? null;
                $failure['failure_reason'] = is_string($message) ? ($reasons[$message] ?? 'unclassified') : 'unclassified';
            }
            return $failure;
        } catch (\Throwable $error) {
            // Child/model diagnostics can contain private settings.
            $failure['failure_reason'] = 'backend_exception';
            return $failure;
        }
    }
}
