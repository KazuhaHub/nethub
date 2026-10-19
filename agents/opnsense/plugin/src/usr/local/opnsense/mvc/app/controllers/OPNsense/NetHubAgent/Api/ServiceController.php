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
        $result = json_decode($backend->configdRun('nethub-agent ' . $action), true);
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
}
