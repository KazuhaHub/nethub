<?php

namespace OPNsense\NetHubAgent\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = 'OPNsense\NetHubAgent\NetHubAgent';
    protected static $internalModelName = 'nethubagent';

    protected function getModelNodes()
    {
        return ['enabled' => (string)$this->getModel()->enabled];
    }

    public function setAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $settings = $this->request->getPost('nethubagent');
        if (
            !is_array($settings) || array_keys($settings) !== ['enabled'] ||
            !in_array($settings['enabled'], ['0', '1'], true)
        ) {
            return ['result' => 'failed', 'message' => gettext('Only the Enable setting can be changed.')];
        }
        return parent::setAction();
    }

    public function debugGetAction()
    {
        $model = $this->getModel();
        $settings = [];
        foreach (['server_addr', 'server_port', 'subdomain', 'device_id'] as $name) {
            $settings[$name] = (string)$model->$name;
        }
        // Credentials are write-only, including the temporary W2 debug interface.
        $settings['frp_token'] = '';
        $settings['domain_claim'] = '';
        return ['nethubagent' => $settings];
    }

    public function debugSetAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $settings = $this->request->getPost('nethubagent');
        $allowed = ['server_addr', 'server_port', 'subdomain', 'device_id', 'frp_token', 'domain_claim'];
        if (!is_array($settings) || count($settings) === 0 || array_diff(array_keys($settings), $allowed)) {
            return ['result' => 'failed'];
        }
        foreach ($settings as $value) {
            if (!is_string($value)) {
                return ['result' => 'failed'];
            }
        }
        // Blank secrets retain the stored value. Model validation rejects invalid replacements.
        foreach (['frp_token', 'domain_claim'] as $name) {
            if (isset($settings[$name]) && $settings[$name] === '') {
                unset($settings[$name]);
            }
        }
        \OPNsense\Core\Config::getInstance()->lock();
        $this->getModel()->setNodes($settings);
        $result = $this->validate();
        return empty($result['result']) ? $this->save(false, true) : $result;
    }
}
