<?php

// Private CLI boundary: public transaction identifiers enter through stdin.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (): never {
    throw new RuntimeException('Native GUI certificate operation failed');
});

try {
    if ($argc !== 1) {
        throw new RuntimeException('Unexpected native certificate arguments');
    }
    $raw = stream_get_contents(STDIN, 16385);
    if ($raw === false || strlen($raw) > 16384) {
        throw new RuntimeException('Native certificate request exceeds its limit');
    }
    $input = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($input) || count($input) !== 2 || !is_string($input['action'] ?? null) || !is_array($input['request'] ?? null)) {
        throw new RuntimeException('Invalid native certificate request');
    }
    $expected = $input['action'] === 'prepare' ? ['candidate_sha256', 'last_good', 'nonce'] :
        ['candidate_sha256', 'nonce', 'snapshot_sha256'];
    $fields = array_keys($input['request']);
    sort($fields);
    if ($fields !== $expected || !in_array($input['action'], ['prepare', 'install', 'check', 'rollback'], true)) {
        throw new RuntimeException('Invalid native certificate operation');
    }
    require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
    require_once(__DIR__ . '/gui_certificate_store.php');
    $configIdentity = NativeGuiCertificateStore::configurationIdentity((string)(new \OPNsense\Core\AppConfig())->globals->owner);
    $store = new NativeGuiCertificateStore(\OPNsense\Core\Config::getInstance(),
        '/usr/local/etc/nethub-agent/gui-apply', '/conf/config.xml', '/var/db/nethub-agent', 0, $configIdentity);
    $result = $store->dispatch($input['action'], $input['request']);
    echo json_encode(['success' => true, 'result' => $result], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    $failure = ['success' => false, 'message' => 'Native GUI certificate operation failed; local recovery may be required'];
    if ($error instanceof NativeGuiCertificatePrerequisite && $error->reason === 'alternate_hostname_required') {
        $failure = ['success' => false, 'code' => 'alternate_hostname_required',
            'message' => 'Add the assigned host to native Alternate Hostnames before applying a GUI certificate'];
    }
    echo json_encode($failure, JSON_THROW_ON_ERROR);
    exit(1);
}
