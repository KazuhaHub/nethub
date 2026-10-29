<?php

// Root-only native model boundary; private credential requests enter through stdin.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (int $severity, string $message, string $file, int $line): never {
    throw new ErrorException('Native rotation operation failed', 0, $severity, $file, $line);
});
$phase = 'arguments';
try {
    if ($argc !== 1) { throw new RuntimeException('Unexpected native rotation arguments'); }
    // Appliance PHP has no POSIX extension. The Python caller checks effective
    // UID; this protected root-owned lock also excludes unprivileged CLI use.
    $phase = 'private_lock';
    $path = '/var/db/nethub-agent/reconcile.lock';
    $info = lstat($path);
    if ($info === false || ($info['mode'] & 0170000) !== 0100000 || $info['uid'] !== 0 ||
        ($info['mode'] & 0777) !== 0600 || $info['nlink'] !== 1 || realpath($path) !== $path) {
        throw new RuntimeException('Native rotation operations require protected storage');
    }
    $lock = fopen($path, 'rb');
    try {
        $opened = fstat($lock);
        if ($opened['dev'] !== $info['dev'] || $opened['ino'] !== $info['ino']) {
            throw new RuntimeException('Native rotation lock changed');
        }
    } finally { fclose($lock); }
    $phase = 'private_input';
    $raw = stream_get_contents(STDIN, 131073);
    if ($raw === false || strlen($raw) > 131072) { throw new RuntimeException('Native rotation request exceeds its limit'); }
    $input = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($input) || array_keys($input) !== ['action', 'request'] ||
        !is_string($input['action']) || !is_array($input['request'])) {
        throw new RuntimeException('Invalid native rotation request');
    }
    $phase = 'native_load';
    require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
    require_once(__DIR__ . '/gui_certificate_store.php');
    require_once(__DIR__ . '/rotation_store.php');
    require_once('/usr/local/opnsense/mvc/app/models/OPNsense/NetHubAgent/Enrollment.php');
    $phase = 'native_identity';
    $identity = NativeGuiCertificateStore::configurationIdentity((string)(new \OPNsense\Core\AppConfig())->globals->owner);
    $phase = 'native_store';
    $store = new NativeRotationStore(\OPNsense\Core\Config::getInstance(),
        static fn() => new \OPNsense\NetHubAgent\NetHubAgent(), '/conf/config.xml', $identity, '/var/db/nethub-agent');
    $phase = 'native_dispatch';
    echo json_encode(['success' => true, 'result' => $store->dispatch($input['action'], $input['request'])], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    $sources = ['rotation_model.php' => 'entry', 'rotation_store.php' => 'store',
                'gui_certificate_store.php' => 'gui_store', 'AppConfig.php' => 'app_config',
                'Config.php' => 'config', 'BaseModel.php' => 'model', 'Enrollment.php' => 'enrollment'];
    $source = $sources[basename($error->getFile())] ?? 'other';
    $kind = get_class($error);
    echo json_encode(['success' => false,
        'message' => 'Native credential rotation model operation failed; local recovery may be required',
        'native_phase' => $phase,
        'failure_context' => [
            'kind' => in_array($kind, ['Error', 'ErrorException', 'TypeError', 'ValueError', 'RuntimeException'], true)
                ? $kind : 'other',
            'source' => $source,
            'line' => $source !== 'other' && $error->getLine() <= 20000 ? $error->getLine() : 0,
        ]], JSON_THROW_ON_ERROR);
    exit(1);
}
