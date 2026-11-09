<?php

namespace OPNsense\Base {
    class ApiControllerBase {
        public $request;
        public $readonly = false;
        protected function throwReadOnly() {
            if ($this->readonly) { throw new \RuntimeException('readonly'); }
        }
    }
}
namespace OPNsense\Core {
    class Backend {
        public function configdRun($action, $detach = null, $timeout = null) {
            if ($detach !== false || $timeout !== ($action === 'nethub-agent rotate' ? 100 : 40) ||
                !in_array($action, ['nethub-agent disable', 'nethub-agent enable', 'nethub-agent rotate'], true)) {
                throw new \RuntimeException('unexpected backend command');
            }
            $GLOBALS['calls'][] = $action;
            if ($GLOBALS['backend_throw'] ?? false) { throw new \RuntimeException('private-fixture-value'); }
            return $GLOBALS['response'];
        }
    }
}
namespace {
    require $argv[1];
    $passed = [];
    foreach (['disable', 'enable', 'rotate'] as $action) {
        foreach (['get', 'readonly', 'success', 'busy', 'invalid', 'trust_changed'] as $case) {
            $GLOBALS['calls'] = [];
            $GLOBALS['response'] = $case === 'invalid' ? 'invalid JSON' :
                json_encode(['success' => $case === 'success', 'action' => $case === 'busy' ? 'busy' : $action,
                    'phase' => $case === 'success' ? 'applied' : ($case === 'trust_changed' ? 'trust_changed' : 'error'), 'message' => 'private-fixture-value',
                    'device_secret' => 'private-fixture-value']);
            $controller = new \OPNsense\NetHubAgent\Api\ServiceController();
            $controller->readonly = $case === 'readonly';
            $controller->request = new class($case) {
                private $case;
                public function __construct($case) { $this->case = $case; }
                public function isPost() { return $this->case !== 'get'; }
            };
            try {
                $result = $controller->{$action . 'Action'}();
                if ($case === 'readonly') { exit(10); }
                if ($result['success'] !== ($case === 'success')) { exit(11); }
                if ($action === 'rotate' && str_contains(json_encode($result), 'private-fixture-value')) { exit(15); }
                if ($action === 'rotate' && $case === 'trust_changed' && ($result['phase'] ?? null) !== 'trust_changed') { exit(16); }
            } catch (\RuntimeException $error) {
                if ($case !== 'readonly' || $error->getMessage() !== 'readonly') { throw $error; }
            }
            $expected = in_array($case, ['get', 'readonly'], true) ? [] : ['nethub-agent ' . $action];
            if ($GLOBALS['calls'] !== $expected) { exit(12); }
            $passed[] = $action . ':' . $case;
        }
    }
    $failures = [
        ['Relay trust synchronization failed; inspect trust and recovery status', 'trust_sync'],
        ['Pending relay trust recovery failed; tunnel startup is blocked', 'trust_recovery'],
        ['Managed trust needs local review; retain the rotation journal', 'trust_recovery'],
        ['Native rotation model operation failed', 'native_model'],
        ['Rotation storage or original assignment needs local review', 'rotation_journal'],
        ['Native rotation model save is unconfirmed', 'native_save'],
        ['Native rotation save is unconfirmed; retain the journal', 'native_save'],
        ['Rotation interrupted; retain the private journal and retry.', 'interrupted'],
        ['private-fixture-value', 'unclassified'],
        [['private-fixture-value'], 'unclassified'],
    ];
    $reasons = [];
    foreach ($failures as [$message, $reason]) {
        $GLOBALS['response'] = json_encode(['success' => false, 'action' => 'rotate',
            'phase' => 'error', 'message' => $message, 'device_secret' => 'private-fixture-value']);
        $result = $controller->rotateAction();
        if ($result['success'] !== false || $result['phase'] !== 'error' ||
            $result['failure_reason'] !== $reason || str_contains(json_encode($result), 'private-fixture-value')) { exit(17); }
        $reasons[] = $reason;
    }
    foreach (['invalid JSON', str_repeat('x', 4097), json_encode(['success' => 'private-fixture-value'])] as $raw) {
        $GLOBALS['response'] = $raw;
        if ($controller->rotateAction()['failure_reason'] !== 'backend_response') { exit(18); }
        $reasons[] = 'backend_response';
    }
    $GLOBALS['backend_throw'] = true;
    $result = $controller->rotateAction();
    if ($result['failure_reason'] !== 'backend_exception' || str_contains(json_encode($result), 'private-fixture-value')) { exit(19); }
    $reasons[] = 'backend_exception';
    echo json_encode(['service_cases_passed' => $passed, 'rotation_failure_cases_passed' => $reasons]);
}
