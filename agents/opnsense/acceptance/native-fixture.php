<?php

// Disposable guest provisioning only; this file is never installed in the plugin.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (): never { throw new RuntimeException('Fixture failed'); });

try {
    if ($argc !== 1 || PHP_SAPI !== 'cli' || PHP_OS_FAMILY !== 'BSD' || posix_geteuid() !== 0) {
        throw new RuntimeException('Wrong fixture host');
    }
    $marker = '/root/nethub-ci/native-fixture-nonce';
    $stat = lstat($marker);
    if ($stat === false || is_link($marker) || $stat['uid'] !== 0 || $stat['nlink'] !== 1 ||
        ($stat['mode'] & 0777) !== 0600 || !is_file('/root/nethub-ci/sshd.conf')) {
        throw new RuntimeException('Missing private fixture identity');
    }
    $raw = stream_get_contents(STDIN, 65537);
    if ($raw === false || strlen($raw) > 65536) {
        throw new RuntimeException('Oversize fixture request');
    }
    $request = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($request) || !is_string($request['nonce'] ?? null) ||
        !preg_match('/\A[a-f0-9]{32}\z/D', $request['nonce']) ||
        !hash_equals(trim(file_get_contents($marker)), $request['nonce'])) {
        throw new RuntimeException('Wrong fixture identity');
    }
    $action = $request['action'] ?? '';
    $expected = match ($action) {
        'trust' => ['action', 'ca_pem', 'nonce'],
        'csr', 'inspect' => ['action', 'host', 'nonce'],
        'install' => ['action', 'ca_pem', 'certificate_pem', 'host', 'nonce'],
        default => throw new RuntimeException('Unknown fixture operation'),
    };
    $fields = array_keys($request);
    sort($fields);
    if ($fields !== $expected) {
        throw new RuntimeException('Unexpected fixture fields');
    }
    require_once('/usr/local/opnsense/mvc/script/load_phalcon.php');
    $configuration = \OPNsense\Core\Config::getInstance();
    $configuration->lock();
    try {
        $root = $configuration->object();
        $gui = $root->system->webgui;
        if (isset($gui->nodnsrebindcheck) || isset($gui->nohttpreferercheck)) {
            throw new RuntimeException('Native GUI checks must stay enabled');
        }
        if ($action === 'trust') {
            $pem = $request['ca_pem'];
            $ca = is_string($pem) ? openssl_x509_read($pem) : false;
            $info = $ca === false ? false : openssl_x509_parse($ca);
            if ($info === false || !str_contains($info['extensions']['basicConstraints'] ?? '', 'CA:TRUE') ||
                openssl_x509_verify($ca, openssl_pkey_get_public($ca)) !== 1) {
                throw new RuntimeException('Invalid fixture CA');
            }
            $entry = $root->addChild('ca');
            $entry->addChild('refid', 'nhfixture' . substr($request['nonce'], 0, 16));
            $entry->addChild('descr', 'NetHub isolated console fixture');
            $entry->addChild('crt', base64_encode($pem));
            $configuration->save();
            $result = ['trusted' => true];
        } else {
            $host = $request['host'];
            if (!is_string($host) || !preg_match('/\A[a-z0-9]{8}\.router\.example\.com\z/D', $host) ||
                (string)$root->OPNsense->NetHubAgent->subdomain !== explode('.', $host)[0]) {
                throw new RuntimeException('Fixture host differs from native enrollment');
            }
            $reference = (string)$gui->{'ssl-certref'};
            $matches = [];
            foreach ($root->cert as $certificate) {
                if ((string)$certificate->refid === $reference) {
                    $matches[] = $certificate;
                }
            }
            if (count($matches) !== 1) {
                throw new RuntimeException('Ambiguous native GUI certificate');
            }
            $entry = $matches[0];
            $key = openssl_pkey_get_private(base64_decode((string)$entry->prv, true));
            $old = openssl_x509_read(base64_decode((string)$entry->crt, true));
            if ($key === false || $old === false || !openssl_x509_check_private_key($old, $key)) {
                throw new RuntimeException('Invalid existing native GUI identity');
            }
            $result = ['key_sha256' => hash('sha256', openssl_pkey_get_details($key)['key']),
                       'security_checks_enabled' => true];
            if ($action === 'csr') {
                $csr = openssl_csr_new(['commonName' => $host], $key, ['digest_alg' => 'sha256']);
                if ($csr === false || !openssl_csr_export($csr, $public)) {
                    throw new RuntimeException('Public native CSR unavailable');
                }
                $result['csr_pem'] = $public;
            } elseif ($action === 'install') {
                $leaf = openssl_x509_read($request['certificate_pem']);
                $ca = openssl_x509_read($request['ca_pem']);
                $info = $leaf === false ? false : openssl_x509_parse($leaf);
                if ($info === false || $ca === false ||
                    ($info['extensions']['subjectAltName'] ?? '') !== 'DNS:' . $host ||
                    $info['validFrom_time_t'] > time() || $info['validTo_time_t'] <= time() ||
                    !openssl_x509_check_private_key($leaf, $key) ||
                    openssl_x509_verify($leaf, openssl_pkey_get_public($ca)) !== 1) {
                    throw new RuntimeException('Fixture certificate differs from native key/host');
                }
                $entry->crt = base64_encode($request['certificate_pem']);
                $alternates = preg_split('/\s+/', trim((string)$gui->althostnames), -1, PREG_SPLIT_NO_EMPTY);
                if (!in_array($host, $alternates, true)) {
                    $alternates[] = $host;
                }
                $gui->althostnames = implode(' ', $alternates);
                $configuration->save();
                $result['installed'] = true;
            } else {
                $result['alternate_present'] = in_array($host,
                    preg_split('/\s+/', trim((string)$gui->althostnames)), true);
            }
        }
    } finally {
        $configuration->unlock();
    }
    if ($action === 'trust') {
        require_once('/usr/local/etc/inc/config.inc');
        require_once('/usr/local/etc/inc/system.inc');
        $config = $configuration->toArray();
        ob_start();
        system_trust_configure();
        ob_end_clean();
    }
    echo json_encode(['success' => true, 'result' => $result], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    echo '{"success":false}';
    exit(1);
}
