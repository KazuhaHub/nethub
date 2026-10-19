<?php

namespace OPNsense\NetHubAgent\Api;

use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\NetHubAgent\Enrollment;
use OPNsense\NetHubAgent\NetHubAgent;

class EnrollController extends \OPNsense\Base\ApiControllerBase
{
    private const REQUESTS = '/var/db/nethub-agent/requests';

    public function getAction()
    {
        $model = new NetHubAgent();
        $result = ['enrolled' => (string)$model->device_id !== ''];
        foreach (['console_url', 'device_id', 'server_addr', 'server_name', 'subdomain'] as $field) {
            $result[$field] = (string)$model->$field;
        }
        return $result;
    }

    private function failure($message = 'Enrollment failed; check the address, token and console availability.')
    {
        return ['success' => false, 'message' => gettext($message)];
    }

    public function enrollAction()
    {
        if (!$this->request->isPost()) {
            return $this->failure();
        }
        $this->throwReadOnly();
        if (!is_dir(self::REQUESTS) || is_link(self::REQUESTS) || realpath(self::REQUESTS) !== self::REQUESTS ||
            fileowner(self::REQUESTS) !== 0 || (fileperms(self::REQUESTS) & 0777) !== 0700) {
            return $this->failure('Private enrollment storage is unavailable.');
        }
        $lockPath = self::REQUESTS . '/enrollment.lock';
        if (is_link($lockPath)) {
            return $this->failure();
        }
        $oldMask = umask(0077);
        $lock = @fopen($lockPath, 'c');
        umask($oldMask);
        if ($lock === false) {
            return $this->failure();
        }
        $requestPath = null;
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                return $this->failure('Another enrollment is in progress.');
            }
            $model = new NetHubAgent();
            if ((string)$model->device_id !== '') {
                return ['success' => true, 'enrolled' => true, 'message' => gettext('Device is already enrolled.')];
            }
            $origin = Enrollment::origin($this->request->getPost('origin'));
            $token = $this->request->getPost('token');
            if ($origin === null || !Enrollment::token($token)) {
                return $this->failure('Enter a console HTTPS address and a valid enrollment token.');
            }
            $requestPath = self::REQUESTS . '/enroll-' . bin2hex(random_bytes(16)) . '.json';
            $oldMask = umask(0077);
            $stream = @fopen($requestPath, 'x');
            umask($oldMask);
            if ($stream === false) {
                return $this->failure();
            }
            try {
                $data = json_encode(['origin' => $origin, 'token' => $token], JSON_THROW_ON_ERROR);
                if (fwrite($stream, $data) !== strlen($data) || !fflush($stream) || !fsync($stream)) {
                    return $this->failure();
                }
            } finally {
                fclose($stream);
            }
            unset($token, $data);
            $backend = new Backend();
            $raw = $backend->configdpRun('nethub-agent enroll', [$requestPath], false, 35);
            if (!is_string($raw) || strlen($raw) > 65536) {
                return $this->failure();
            }
            $response = json_decode($raw, true, 16);
            unset($raw);
            $assignment = is_array($response) && ($response['success'] ?? null) === true
                ? Enrollment::assignment($response['assignment'] ?? null) : null;
            if ($assignment === null) {
                return $this->failure();
            }
            $config = Config::getInstance();
            $config->lock();
            try {
                // Construct the model after acquiring the native lock and reloading current configuration.
                $model = new NetHubAgent();
                if ((string)$model->device_id !== '') {
                    return $this->failure('Configuration changed during enrollment; review local settings.');
                }
                $settings = array_intersect_key($assignment, array_flip([
                    'device_id', 'device_secret', 'frp_token', 'server_addr', 'server_name', 'subdomain', 'domain_claim'
                ]));
                $settings['server_port'] = (string)$assignment['server_port'];
                $settings['console_url'] = $origin;
                $settings['relay_ca'] = base64_encode($assignment['relay_ca_pem']);
                $settings['enabled'] = '1';
                $model->setNodes($settings);
                if (count($model->performValidation()) !== 0) {
                    return $this->failure('The assignment could not be saved; local settings were retained.');
                }
                $model->serializeToConfig();
                $config->save(['description' => 'NetHub device enrolled']);
            } finally {
                $config->unlock();
            }
            unset($assignment, $settings, $response);
            $applied = json_decode($backend->configdRun('nethub-agent start', false, 35), true);
            $ready = is_array($applied) && ($applied['success'] ?? false) === true;
            return ['success' => true, 'enrolled' => true, 'tunnel_ready' => $ready,
                'message' => gettext($ready ? 'Enrollment saved; tunnel service started.' :
                    'Enrollment saved; tunnel setup needs attention. Check status and retry Apply.')];
        } catch (\Throwable $error) {
            // Framework/child diagnostics may contain credentials. Return only a fixed failure.
            return $this->failure();
        } finally {
            if ($requestPath !== null && is_file($requestPath) && !is_link($requestPath)) {
                @unlink($requestPath);
            }
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
