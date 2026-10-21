<?php

// Root-only native model boundary; public requests enter through stdin.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (): never { throw new RuntimeException('Native trust operation failed'); });
try {
    if ($argc !== 1) { throw new RuntimeException('Unexpected native trust arguments'); }
    // Appliance PHP has no POSIX extension. The Python caller checks effective
    // UID; this protected root-owned lock also excludes unprivileged CLI use.
    $path = '/var/db/nethub-agent/reconcile.lock';
    $info = lstat($path);
    if ($info === false || ($info['mode'] & 0170000) !== 0100000 || $info['uid'] !== 0 ||
        ($info['mode'] & 0777) !== 0600 || $info['nlink'] !== 1 || realpath($path) !== $path) {
        throw new RuntimeException('Native trust operations require protected storage');
    }
    $lock = fopen($path, 'rb');
    try {
        $opened = fstat($lock);
        if ($opened['dev'] !== $info['dev'] || $opened['ino'] !== $info['ino']) {
            throw new RuntimeException('Native trust lock changed');
        }
    } finally { fclose($lock); }
    $raw = stream_get_contents(STDIN, 131073);
    if ($raw === false || strlen($raw) > 131072) { throw new RuntimeException('Native trust request exceeds its limit'); }
    $input = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($input) || array_keys($input) !== ['action', 'request'] ||
        !is_string($input['action']) || !is_array($input['request'])) {
        throw new RuntimeException('Invalid native trust request');
    }
    require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
    require_once(__DIR__ . '/gui_certificate_store.php');
    require_once(__DIR__ . '/relay_trust_store.php');
    $identity = NativeGuiCertificateStore::configurationIdentity((string)(new \OPNsense\Core\AppConfig())->globals->owner);
    $store = new NativeRelayTrustStore(\OPNsense\Core\Config::getInstance(),
        static fn() => new \OPNsense\NetHubAgent\NetHubAgent(), '/conf/config.xml', '/var/db/nethub-agent', $identity);
    echo json_encode(['success' => true, 'result' => $store->dispatch($input['action'], $input['request'])], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    echo json_encode(['success' => false, 'message' => 'Native relay trust operation failed; local recovery may be required'], JSON_THROW_ON_ERROR);
    exit(1);
}
