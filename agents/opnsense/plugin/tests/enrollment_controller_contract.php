<?php

namespace OPNsense\Base {
    class ApiControllerBase
    {
        public $request;
        public $readonly = false;
        protected function throwReadOnly()
        {
            if ($this->readonly) {
                throw new \RuntimeException('read only');
            }
        }
    }
}

namespace OPNsense\Core {
    class Config
    {
        public static function getInstance() { return new self(); }
        public function lock() { $GLOBALS['events'][] = 'lock'; }
        public function unlock() { $GLOBALS['events'][] = 'unlock'; }
        public function save($revision) { $GLOBALS['events'][] = 'save'; }
    }
    class Backend
    {
        public function configdpRun($event, $parameters, $detach, $timeout)
        {
            $GLOBALS['events'][] = 'network';
            if ($event !== 'nethub-agent enroll' || count($parameters) !== 1 || $timeout !== 35) {
                throw new \RuntimeException('unexpected backend request');
            }
            $path = $parameters[0];
            if (!preg_match('/\/enroll-[a-f0-9]{32}\.json$/D', $path) || (fileperms($path) & 0777) !== 0600) {
                throw new \RuntimeException('unsafe handoff');
            }
            $request = json_decode(file_get_contents($path), true);
            if ($request !== ['origin' => 'https://console.example.com', 'token' => str_repeat('A', 43)]) {
                throw new \RuntimeException('incorrect private request');
            }
            unlink($path);
            return json_encode(['success' => true, 'assignment' => $GLOBALS['assignment']]);
        }
        public function configdRun($event, $detach, $timeout)
        {
            if ($event !== 'nethub-agent start') {
                throw new \RuntimeException('incorrect service action');
            }
            $GLOBALS['events'][] = 'start';
            return json_encode(['success' => $GLOBALS['start_ready']]);
        }
    }
}

namespace OPNsense\NetHubAgent {
    class NetHubAgent
    {
        private $values;
        public static $saved = [];
        public function __construct()
        {
            $GLOBALS['events'][] = 'model';
            $this->values = self::$saved;
        }
        public function __get($name) { return $this->values[$name] ?? ''; }
        public function setNodes($settings) { $this->values = array_replace($this->values, $settings); }
        public function performValidation() { return $GLOBALS['model_invalid'] ? ['invalid'] : []; }
        public function serializeToConfig()
        {
            $GLOBALS['events'][] = 'serialize';
            self::$saved = $this->values;
            return true;
        }
    }
}

namespace OPNsense\NetHubAgent\Api {
    function fileowner($path)
    {
        // The CLI fixture emulates the appliance root-owned request directory.
        return \fileowner($path) === \getmyuid() ? 0 : \fileowner($path);
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext($text) { return $text; }
    }
    $input = json_decode(stream_get_contents(STDIN), true);
    require $argv[2];
    $source = file_get_contents($argv[1]);
    $needle = "private const REQUESTS = '/var/db/nethub-agent/requests';";
    if (substr_count($source, $needle) !== 1) {
        exit(10);
    }
    $source = str_replace($needle, 'private const REQUESTS = ' . var_export($argv[3], true) . ';', $source);
    eval(substr($source, 5));
    $passed = [];
    foreach (['success', 'start-failed', 'bad-response', 'model-invalid', 'existing', 'get-only', 'readonly', 'busy'] as $case) {
        $GLOBALS['events'] = [];
        $GLOBALS['assignment'] = $input;
        $GLOBALS['start_ready'] = $case !== 'start-failed';
        $GLOBALS['model_invalid'] = $case === 'model-invalid';
        \OPNsense\NetHubAgent\NetHubAgent::$saved = $case === 'existing' ? ['device_id' => 'existing'] : [];
        if ($case === 'bad-response') {
            $GLOBALS['assignment']['server_name'] = 'bad/path';
        }
        $controller = new \OPNsense\NetHubAgent\Api\EnrollController();
        $controller->readonly = $case === 'readonly';
        $controller->request = new class($case) {
            private $case;
            public function __construct($case) { $this->case = $case; }
            public function isPost() { return $this->case !== 'get-only'; }
            public function getPost($field) { return $field === 'origin' ? 'https://console.example.com' : str_repeat('A', 43); }
        };
        $busy = null;
        if ($case === 'busy') {
            $busy = fopen($argv[3] . '/enrollment.lock', 'c');
            flock($busy, LOCK_EX);
        }
        try {
            $response = $controller->enrollAction();
            if ($case === 'readonly') {
                exit(11);
            }
        } catch (\RuntimeException $error) {
            if ($case !== 'readonly') {
                exit(12);
            }
            $response = ['success' => false];
        } finally {
            if ($busy !== null) {
                flock($busy, LOCK_UN);
                fclose($busy);
            }
        }
        $snapshotEvents = $GLOBALS['events'];
        $success = in_array($case, ['success', 'start-failed', 'existing'], true);
        if ($response['success'] !== $success || glob($argv[3] . '/enroll-*.json')) {
            fwrite(STDERR, json_encode(['case' => $case, 'events' => $events, 'success' => $response['success'],
                'request_files' => count(glob($argv[3] . '/enroll-*.json'))]));
            exit(13);
        }
        $browser = json_encode($response) . json_encode($controller->getAction());
        foreach (['device_secret', 'frp_token', 'domain_claim', 'relay_ca_pem', str_repeat('A', 43)] as $forbidden) {
            if (str_contains($browser, $forbidden)) {
                exit(14);
            }
        }
        if (in_array($case, ['success', 'start-failed'], true)) {
            $saved = \OPNsense\NetHubAgent\NetHubAgent::$saved;
            if ($saved['enabled'] !== '1' || $saved['device_id'] !== $input['device_id'] ||
                $saved['console_url'] !== 'https://console.example.com' ||
                base64_decode($saved['relay_ca']) !== $input['relay_ca_pem'] ||
                $saved['server_name'] !== $input['server_name'] ||
                $response['tunnel_ready'] !== ($case === 'success') ||
                array_search('lock', $events) > array_search('serialize', $events) ||
                array_search('save', $events) > array_search('unlock', $events) ||
                end($snapshotEvents) !== 'start') {
                fwrite(STDERR, json_encode(['case' => $case, 'events' => $events, 'ready' => $response['tunnel_ready']]));
                exit(15);
            }
        } elseif (in_array('save', $events, true) || in_array('start', $events, true)) {
            exit(16);
        }
        if (in_array($case, ['existing', 'get-only', 'readonly', 'busy'], true) && in_array('network', $events, true)) {
            exit(17);
        }
        $passed[] = $case;
    }
    echo json_encode(['controller_cases_passed' => $passed]);
}
