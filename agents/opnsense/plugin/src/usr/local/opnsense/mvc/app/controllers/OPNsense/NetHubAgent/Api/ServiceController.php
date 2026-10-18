<?php

namespace OPNsense\NetHubAgent\Api;

class ServiceController extends \OPNsense\Base\ApiControllerBase
{
    public function statusAction()
    {
        return ['status' => 'not_configured', 'message' => gettext('Tunnel integration is not installed.')];
    }
}
