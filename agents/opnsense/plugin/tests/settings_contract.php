<?php

namespace OPNsense\Base {
    class ApiMutableModelControllerBase
    {
        public $request;
        public $saved = false;

        protected function getModel()
        {
            return (object)['enabled' => '0', 'device_secret' => 'must-not-be-returned'];
        }

        public function setAction()
        {
            $this->saved = true;
            return ['result' => 'saved'];
        }
    }
}

namespace {
    require $argv[1];

    class TestSettings extends \OPNsense\NetHubAgent\Api\SettingsController
    {
        public function visibleSettings()
        {
            return $this->getModelNodes();
        }
    }

    if (!function_exists('gettext')) {
        function gettext($text)
        {
            return $text;
        }
    }

    $cases = json_decode(stream_get_contents(STDIN), true);
    foreach ($cases as $case) {
        $controller = new TestSettings();
        $controller->request = new class($case) {
            private $data;
            public function __construct($data) { $this->data = $data; }
            public function isPost() { return $this->data['post']; }
            public function getPost($name) { return $this->data['settings']; }
        };
        $controller->setAction();
        if ($controller->saved !== $case['allowed']) {
            exit(1);
        }
        if ($controller->visibleSettings() !== ['enabled' => '0']) {
            exit(2);
        }
    }
}
