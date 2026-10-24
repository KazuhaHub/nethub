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
            if ($detach !== false || $timeout !== 40 ||
                !in_array($action, ['nethub-agent disable', 'nethub-agent enable'], true)) {
                throw new \RuntimeException('unexpected backend command');
            }
            $GLOBALS['calls'][] = $action;
            return $GLOBALS['response'];
        }
    }
}
namespace {
    require $argv[1];
    $passed = [];
    foreach (['disable', 'enable'] as $action) {
        foreach (['get', 'readonly', 'success', 'busy', 'invalid'] as $case) {
            $GLOBALS['calls'] = [];
            $GLOBALS['response'] = $case === 'invalid' ? 'invalid JSON' :
                json_encode(['success' => $case === 'success', 'action' => $case === 'busy' ? 'busy' : $action]);
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
            } catch (\RuntimeException $error) {
                if ($case !== 'readonly' || $error->getMessage() !== 'readonly') { throw $error; }
            }
            $expected = in_array($case, ['get', 'readonly'], true) ? [] : ['nethub-agent ' . $action];
            if ($GLOBALS['calls'] !== $expected) { exit(12); }
            $passed[] = $action . ':' . $case;
        }
    }
    echo json_encode(['service_cases_passed' => $passed]);
}
