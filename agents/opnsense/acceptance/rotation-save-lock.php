<?php

// Disposable guest fault only; never installed or used by the plugin.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (int $severity): bool {
    if (!(error_reporting() & $severity)) { return false; }
    throw new RuntimeException('Owned lock fixture failed');
});
try {
    if (($argc ?? null) !== 1 || PHP_SAPI !== 'cli' || PHP_OS !== 'FreeBSD') {
        throw new RuntimeException('Wrong lock fixture host');
    }
    $identities = [];
    exec('/usr/bin/id -u', $identities, $status);
    if ($status !== 0 || $identities !== ['0']) { throw new RuntimeException('Effective root required'); }
    $directory = '/root/nethub-ci';
    $marker = $directory . '/native-fixture-nonce';
    $info = lstat($marker);
    if ($info === false || is_link($marker) || $info['uid'] !== 0 || $info['nlink'] !== 1 ||
        ($info['mode'] & 0777) !== 0600) { throw new RuntimeException('Missing owned nonce'); }
    $input = json_decode(stream_get_contents(STDIN, 256), true, 4, JSON_THROW_ON_ERROR);
    if (!is_array($input) || array_keys($input) !== ['nonce'] || !is_string($input['nonce']) ||
        !preg_match('/\A[a-f0-9]{32}\z/D', $input['nonce']) ||
        !hash_equals(trim(file_get_contents($marker)), $input['nonce'])) {
        throw new RuntimeException('Wrong owned nonce');
    }
    $acknowledged = $directory . '/native-save-lock-acquired';
    $release = $directory . '/native-save-lock-release';
    $completed = $directory . '/native-save-lock-completed';
    $ready = $directory . '/native-save-lock-ready';
    foreach ([$acknowledged, $release, $completed, $ready] as $path) {
        if (file_exists($path) || is_link($path)) { throw new RuntimeException('Stale lock fixture state'); }
    }
    require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
    $configuration = \OPNsense\Core\Config::getInstance();
    $prepared = fopen($ready, 'x');
    fwrite($prepared, "1\n");
    fclose($prepared);
    $journal = '/var/db/nethub-agent/rotation.json';
    $deadline = microtime(true) + 25;
    while (!is_file($journal) && microtime(true) < $deadline) {
        clearstatcache(true, $journal);
        usleep(1000);
    }
    $info = lstat($journal);
    if ($info === false || is_link($journal) || $info['uid'] !== 0 || $info['nlink'] !== 1 ||
        ($info['mode'] & 0777) !== 0600) { throw new RuntimeException('Prepared journal unavailable'); }
    $pending = json_decode(file_get_contents($journal), true, 32, JSON_THROW_ON_ERROR);
    if (($pending['phase'] ?? null) !== 'prepared') { throw new RuntimeException('Missed prepared operation'); }
    $configuration->lock();
    try {
        $ack = fopen($acknowledged, 'x');
        fwrite($ack, "1\n");
        fclose($ack);
        $deadline = microtime(true) + 15;
        while (!is_file($release) && microtime(true) < $deadline) {
            clearstatcache(true, $release);
            usleep(10000);
        }
        if (!is_file($release)) { throw new RuntimeException('Owned lock release timed out'); }
    } finally {
        $configuration->unlock();
    }
    $done = fopen($completed, 'x');
    fwrite($done, "1\n");
    fclose($done);
    echo json_encode(['success' => true]);
} catch (Throwable $error) {
    echo json_encode(['success' => false]);
    exit(1);
}
