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

}
