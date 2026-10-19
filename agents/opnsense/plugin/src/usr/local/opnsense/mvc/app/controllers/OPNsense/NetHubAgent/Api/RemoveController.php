<?php

namespace OPNsense\NetHubAgent\Api;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\NetHubAgent\NetHubAgent;

class RemoveController extends \OPNsense\Base\ApiControllerBase
{
    public function removeAction()
    {
        if (!$this->request->isPost()) {
            return ['success' => false];
        }
        $this->throwReadOnly();
        $directory = '/var/db/nethub-agent/requests';
        if (is_link($directory) || realpath($directory) !== $directory || fileowner($directory) !== 0 ||
            (fileperms($directory) & 0777) !== 0700 || is_link($directory . '/enrollment.lock')) {
            return $this->failure();
        }
        $mask = umask(0077);
        $lock = @fopen($directory . '/enrollment.lock', 'c');
        umask($mask);
        if ($lock === false) {
            return $this->failure();
        }
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                return $this->failure('Another enrollment operation is in progress.');
            }
            $model = new NetHubAgent();
            $deviceId = (string)$model->device_id;
            $backend = new Backend();
            $raw = $backend->configdRun('nethub-agent unenroll', false, 40);
            $reply = is_string($raw) && strlen($raw) <= 4096 ? json_decode($raw, true, 8) : null;
            if (!is_array($reply) || ($reply['success'] ?? null) !== true || ($reply['revoked'] ?? null) !== true ||
                ($reply['device_id'] ?? null) !== $deviceId) {
                return $this->failure('Removal is unconfirmed; check status and retry Remove enrollment.');
            }
            $config = Config::getInstance();
            $config->lock();
            try {
                $model = new NetHubAgent();
                if ((string)$model->device_id !== $deviceId) {
                    return $this->failure('Enrollment changed during removal; local review is required.');
                }
                $values = array_fill_keys(['console_url', 'server_addr', 'server_name', 'relay_ca', 'subdomain',
                    'device_id', 'device_secret', 'frp_token', 'domain_claim'], '');
                $values['enabled'] = '0';
                $values['server_port'] = '7000';
                $model->setNodes($values);
                if (count($model->performValidation(true)) !== 0) {
                    return $this->failure();
                }
                $model->serializeToConfig();
                $config->save(['description' => 'NetHub enrollment removed']);
            } finally {
                $config->unlock();
            }
            $raw = $backend->configdRun('nethub-agent forget', false, 40);
            $cleanup = is_string($raw) && strlen($raw) <= 4096 ? json_decode($raw, true, 8) : null;
            $clean = is_array($cleanup) && ($cleanup['success'] ?? null) === true;
            return ['success' => true, 'enrolled' => false, 'cleanup_complete' => $clean,
                'message' => gettext($clean ? 'Enrollment removed.' :
                    'Enrollment removed; runtime cleanup needs attention. Retry Remove enrollment.')];
        } catch (\Throwable $error) {
            return $this->failure();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function failure($message = 'Removal failed; review local status and retry.')
    {
        return ['success' => false, 'message' => gettext($message)];
    }
}
