<?php

namespace OPNsense\NetHubAgent;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/NetHubAgent/index');
        $this->view->settingsForm = $this->getForm('settings');
        $this->view->debugForm = $this->getForm('debug');
    }
}
