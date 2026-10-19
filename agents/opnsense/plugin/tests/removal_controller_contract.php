<?php

namespace OPNsense\Base {
    class ApiControllerBase {
        public $request;
        public $readonly = false;
        protected function throwReadOnly() { if ($this->readonly) { throw new \RuntimeException('readonly'); } }
    }
}
namespace OPNsense\Core {
    class Config {
        public static function getInstance() { return new self(); }
        public function lock() { $GLOBALS['events'][] = 'lock'; }
        public function unlock() { $GLOBALS['events'][] = 'unlock'; }
        public function save($revision) { $GLOBALS['events'][] = 'save'; }
    }
    class Backend {
        public function configdRun($event, $detach, $timeout) {
            if ($detach !== false || $timeout !== 40) { throw new \RuntimeException('backend bound'); }
            if ($event === 'nethub-agent unenroll') {
                $GLOBALS['events'][] = 'notify';
                return json_encode(['success' => $GLOBALS['case'] !== 'unconfirmed', 'revoked' => true,
                    'device_id' => $GLOBALS['case'] === 'wrong-id' ? 'other' : $GLOBALS['initial_id']]);
            }
            if ($event !== 'nethub-agent forget' || !in_array('save', $GLOBALS['events'], true) ||
                \OPNsense\NetHubAgent\NetHubAgent::$saved['device_secret'] !== '') { throw new \RuntimeException('premature clear'); }
            $GLOBALS['events'][] = 'forget';
            return json_encode(['success' => $GLOBALS['case'] !== 'cleanup-failed']);
        }
    }
}
namespace OPNsense\NetHubAgent {
    class NetHubAgent {
        public static $saved = [];
        private $values;
        public function __construct() {
            $this->values = self::$saved;
            if ($GLOBALS['case'] === 'changed-model' && in_array('lock', $GLOBALS['events'], true)) { $this->values['device_id'] = 'changed'; }
        }
        public function __get($key) { return $this->values[$key] ?? ''; }
        public function setNodes($values) { $this->values = array_replace($this->values, $values); }
        public function performValidation($full) { return $full && $GLOBALS['case'] !== 'model-invalid' ? [] : ['invalid']; }
        public function serializeToConfig() { $GLOBALS['events'][] = 'serialize'; self::$saved = $this->values; }
    }
}
namespace OPNsense\NetHubAgent\Api {
    function fileowner($path) { return \fileowner($path) === \getmyuid() ? 0 : \fileowner($path); }
}
namespace {
    if (!function_exists('gettext')) { function gettext($text) { return $text; } }
    $source = file_get_contents($argv[1]);
    $needle = '$directory = \'/var/db/nethub-agent/requests\';';
    if (substr_count($source, $needle) !== 1) { exit(10); }
    eval(substr(str_replace($needle, '$directory = ' . var_export($argv[2], true) . ';', $source), 5));
    $passed = [];
    foreach (['success', 'empty', 'unconfirmed', 'wrong-id', 'model-invalid', 'changed-model', 'cleanup-failed', 'get-only', 'readonly', 'busy'] as $case) {
        $GLOBALS['case'] = $case; $GLOBALS['events'] = [];
        $GLOBALS['initial_id'] = $case === 'empty' ? '' : '11111111-1111-4111-8111-111111111111';
        $saved = ['device_id' => $GLOBALS['initial_id'], 'device_secret' => 'private-credential', 'enabled' => '1', 'cluster_hint' => '1'];
        \OPNsense\NetHubAgent\NetHubAgent::$saved = $saved;
        $controller = new \OPNsense\NetHubAgent\Api\RemoveController();
        $controller->readonly = $case === 'readonly';
        $controller->request = new class($case) {
            private $case;
            public function __construct($value) { $this->case = $value; }
            public function isPost() { return $this->case !== 'get-only'; }
        };
        $busy = null;
        if ($case === 'busy') { $busy = fopen($argv[2] . '/enrollment.lock', 'c'); flock($busy, LOCK_EX); }
        try {
            $reply = $controller->removeAction();
            if ($case === 'readonly') { exit(11); }
        } catch (\RuntimeException $error) {
            if ($case !== 'readonly') { exit(12); }
            $reply = ['success' => false];
        } finally {
            if ($busy !== null) { flock($busy, LOCK_UN); fclose($busy); }
        }
        $success = in_array($case, ['success', 'empty', 'cleanup-failed'], true);
        if ($reply['success'] !== $success || str_contains(json_encode($reply), 'private-credential')) { exit(13); }
        $events = $GLOBALS['events'];
        if ($success) {
            $actual = \OPNsense\NetHubAgent\NetHubAgent::$saved;
            foreach (['console_url', 'server_addr', 'server_name', 'relay_ca', 'subdomain', 'device_id', 'device_secret', 'frp_token', 'domain_claim'] as $key) {
                if (($actual[$key] ?? null) !== '') { exit(14); }
            }
            if ($actual['enabled'] !== '0' || $actual['cluster_hint'] !== '1' ||
                array_search('notify', $events) > array_search('lock', $events) ||
                array_search('lock', $events) > array_search('serialize', $events) ||
                array_search('save', $events) > array_search('unlock', $events) || end($events) !== 'forget' ||
                $reply['cleanup_complete'] !== ($case !== 'cleanup-failed')) { exit(15); }
        } elseif (\OPNsense\NetHubAgent\NetHubAgent::$saved !== $saved || in_array('forget', $events, true)) { exit(16); }
        if (in_array($case, ['get-only', 'readonly', 'busy'], true) && in_array('notify', $events, true)) { exit(17); }
        $passed[] = $case;
    }
    echo json_encode(['removal_cases_passed' => $passed]);
}
