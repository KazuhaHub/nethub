<?php

final class NativeGuiCertificatePrerequisite extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct('A native GUI prerequisite is missing');
    }
}

/** Native certificate-store operations; callers supply the shared mutation lock. */
final class NativeGuiCertificateStore
{
    private const GOOD = ['candidate_sha256', 'device_id', 'generation', 'generation_id', 'issued_sha256', 'native_hash', 'refid'];

    public function __construct(
        private object $configuration,
        private string $directory,
        private string $configFile,
        private string $stateDirectory = '/var/db/nethub-agent',
        private int $owner = 0
    )
    {
        $this->protect(dirname($directory), true);
        $this->protect($directory, true);
        $resolved = realpath($configFile);
        if ($resolved === false) {
            throw new RuntimeException('Native configuration path is unavailable');
        }
        $this->configFile = $resolved;
        $this->protect($this->configFile, false, true);
    }

    private function protect(string $path, bool $directory = false, bool $config = false): array
    {
        clearstatcache(true, $path);
        $info = lstat($path);
        $type = $directory ? 0040000 : 0100000;
        $modes = $directory ? [0700] : ($config ? [0600, 0640] : [0600]);
        if ($info === false || ($info['mode'] & 0170000) !== $type || $info['uid'] !== $this->owner ||
            !in_array($info['mode'] & 0777, $modes, true) || (!$directory && $info['nlink'] !== 1) ||
            realpath($path) !== $path) {
            throw new RuntimeException('Native certificate storage needs local review');
        }
        return $info;
    }

    private function read(string $path, int $maximum): string
    {
        $before = $this->protect($path);
        if ($before['size'] < 1 || $before['size'] > $maximum) {
            throw new RuntimeException('Invalid protected native material size');
        }
        $stream = fopen($path, 'rb');
        try {
            $opened = fstat($stream);
            if ($opened['ino'] !== $before['ino'] || $opened['dev'] !== $before['dev']) {
                throw new RuntimeException('Protected native material changed');
            }
            $value = stream_get_contents($stream, $maximum + 1);
            if ($value === false || strlen($value) > $maximum) {
                throw new RuntimeException('Invalid protected native material');
            }
            return $value;
        } finally {
            fclose($stream);
        }
    }

    private function canonical(mixed $value): string
    {
        if (is_array($value)) {
            if (!array_is_list($value)) {
                ksort($value);
            }
            foreach ($value as $key => $field) {
                $value[$key] = json_decode($this->canonical($field), true, 32, JSON_THROW_ON_ERROR);
            }
        }
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private function journal(): ?array
    {
        $path = $this->directory . '/transaction.json';
        if (!file_exists($path) && !is_link($path)) {
            return null;
        }
        $raw = $this->read($path, 8192);
        $value = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($value) || ($value['version'] ?? null) !== 1 || $this->canonical($value) . "\n" !== $raw) {
            throw new RuntimeException('Invalid native transaction journal');
        }
        return $value;
    }

    private function cert(SimpleXMLElement $root, string $ref): ?SimpleXMLElement
    {
        $found = null;
        foreach ($root->cert as $node) {
            if ((string)$node->refid === $ref) {
                if ($found !== null) {
                    throw new RuntimeException('Ambiguous native certificate reference');
                }
                $found = $node;
            }
        }
        return $found;
    }

    private function node(string $xml): SimpleXMLElement
    {
        if (strlen($xml) > 524288 || stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) {
            throw new RuntimeException('Invalid native certificate snapshot');
        }
        $document = new DOMDocument();
        $document->preserveWhiteSpace = false;
        if (!$document->loadXML($xml, LIBXML_NONET | LIBXML_NOBLANKS) || $document->documentElement->tagName !== 'cert') {
            throw new RuntimeException('Invalid native certificate snapshot');
        }
        return simplexml_import_dom($document->documentElement);
    }

    private function hash(?SimpleXMLElement $node): ?string
    {
        return $node === null ? null : hash('sha256', dom_import_simplexml($this->node($node->asXML()))->C14N());
    }

    private function replace(SimpleXMLElement $root, string $ref, ?string $xml): void
    {
        $current = $this->cert($root, $ref);
        $parent = dom_import_simplexml($root);
        $replacement = $xml === null ? null : $this->node($xml);
        if ($replacement !== null && (string)$replacement->refid !== $ref) {
            throw new RuntimeException('Native snapshot reference differs');
        }
        $imported = $replacement === null ? null : $parent->ownerDocument->importNode(dom_import_simplexml($replacement), true);
        if ($current !== null) {
            if ($imported === null) {
                $parent->removeChild(dom_import_simplexml($current));
            } else {
                $parent->replaceChild($imported, dom_import_simplexml($current));
            }
        } elseif ($imported !== null) {
            $parent->appendChild($imported);
        }
    }

    private function save(): void
    {
        $this->configuration->save(['description' => 'NetHub GUI certificate configuration']);
        $this->protect($this->configFile, false, true);
        $stream = fopen($this->configFile, 'r+b');
        try {
            if (!fsync($stream)) {
                throw new RuntimeException('Native configuration flush failed');
            }
        } finally {
            fclose($stream);
        }
    }

    private function selected(SimpleXMLElement $root): string
    {
        $gui = $root->system->webgui;
        $ref = (string)$gui->{'ssl-certref'};
        if ((string)$gui->protocol !== 'https' || !preg_match('/\A[a-zA-Z0-9._-]{1,128}\z/D', $ref) || $this->cert($root, $ref) === null) {
            throw new RuntimeException('Native GUI selection needs local review');
        }
        return $ref;
    }

    private function active(SimpleXMLElement $root, array $value): void
    {
        $model = $root->OPNsense->NetHubAgent;
        if ((string)$model->enabled !== '1' || (string)$model->device_id !== $value['device_id'] ||
            (string)$model->subdomain !== explode('.', $value['host'])[0]) {
            throw new RuntimeException('Native enrollment is no longer active');
        }
        if (file_exists($this->stateDirectory) || is_link($this->stateDirectory)) {
            $this->protect($this->stateDirectory, true);
        }
        foreach (['disabled', 'stopped', 'revoked', 'uninstalling'] as $marker) {
            if (file_exists($this->stateDirectory . '/' . $marker) || is_link($this->stateDirectory . '/' . $marker)) {
                throw new RuntimeException('Native service intent prevents certificate application');
            }
        }
    }

    private function writeSnapshot(string $nonce, array $value): string
    {
        $raw = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        if (strlen($raw) > 1048576) {
            throw new RuntimeException('Native snapshot exceeds its limit');
        }
        $path = $this->directory . '/snapshot-' . $nonce . '.json';
        $stream = fopen($path, 'x+b');
        try {
            if (!chmod($path, 0600)) {
                throw new RuntimeException('Native snapshot protection failed');
            }
            for ($offset = 0; $offset < strlen($raw); $offset += $written) {
                $written = fwrite($stream, substr($raw, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('Native snapshot write failed');
                }
            }
            if (!fflush($stream) || !fsync($stream)) {
                throw new RuntimeException('Native snapshot flush failed');
            }
        } finally {
            fclose($stream);
        }
        $this->protect($path);
        return hash('sha256', $raw);
    }

    private function prepare(SimpleXMLElement $root, array $request): array
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $request['nonce'] ?? '') ||
            !preg_match('/\A[a-f0-9]{64}\z/D', $request['candidate_sha256'] ?? '')) {
            throw new RuntimeException('Invalid native preparation identity');
        }
        $stage = $this->read(dirname($this->directory) . '/gui-certificate.json', 65536);
        if (!hash_equals($request['candidate_sha256'], hash('sha256', $stage))) {
            throw new RuntimeException('Verified staged certificate changed');
        }
        $candidate = json_decode($stage, true, 32, JSON_THROW_ON_ERROR);
        $issued = $candidate['issued'];
        $device = $candidate['device_id'];
        $host = $candidate['assigned_host'];
        if (!is_array($issued) || !preg_match('/\A[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\z/D', $device) ||
            !preg_match('/\A[a-z0-9]{8}(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\z/D', $host) || strlen($host) > 253) {
            throw new RuntimeException('Invalid native candidate binding');
        }
        $this->active($root, ['device_id' => $device, 'host' => $host]);
        $alternates = preg_split('/\s+/', trim((string)$root->system->webgui->althostnames));
        if (!in_array($host, array_map('strtolower', $alternates), true)) {
            throw new NativeGuiCertificatePrerequisite('alternate_hostname_required');
        }
        $beforeRef = $this->selected($root);
        $prior = $this->journal();
        if ($prior !== null && !in_array($prior['phase'] ?? '', ['applied', 'rolled_back'], true)) {
            throw new RuntimeException('Native transaction still needs recovery');
        }
        $good = null;
        if ($prior !== null) {
            $good = $prior['phase'] === 'applied' ? array_intersect_key($prior, array_flip(self::GOOD)) : $prior['last_good'];
        }
        if ($this->canonical($request['last_good'] ?? null) !== $this->canonical($good)) {
            throw new RuntimeException('Native last-good identity differs');
        }
        $description = 'NetHub managed GUI ' . $device;
        if ($good !== null) {
            $ref = $good['refid'];
            $before = $this->cert($root, $ref);
            if ($good['device_id'] !== $device || $beforeRef !== $ref || $this->hash($before) !== $good['native_hash'] ||
                (string)$before->descr !== $description) {
                throw new RuntimeException('Native managed selection was changed');
            }
        } else {
            foreach ($root->cert as $existing) {
                if ((string)$existing->descr === $description) {
                    throw new RuntimeException('Untracked native certificate needs local review');
                }
            }
            do {
                $ref = substr(bin2hex(random_bytes(7)), 0, 13);
            } while ($this->cert($root, $ref) !== null);
            $before = null;
        }
        $keyDirectory = dirname($this->directory) . '/gui-key';
        $this->protect($keyDirectory, true);
        $pem = $this->read($keyDirectory . '/key.pem', 4096);
        $key = openssl_pkey_get_private($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        $chain = $issued['chain_pem'];
        $leaf = is_string($chain) && strlen($chain) <= 32768 ? openssl_x509_read($chain) : false;
        $parsed = $leaf === false ? false : openssl_x509_parse($leaf);
        $spki = $details === false ? false : base64_decode(preg_replace('/\s+/', '', str_replace(
            ['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'], '', $details['key'])), true);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_EC ||
            !in_array($details['ec']['curve_name'] ?? '', ['prime256v1', 'secp256r1'], true) || $spki === false ||
            hash('sha256', $spki) !== $candidate['gui_key_fingerprint'] || $leaf === false ||
            !openssl_x509_check_private_key($leaf, $key) || openssl_x509_fingerprint($leaf, 'sha256') !== $issued['leaf_fingerprint'] ||
            ($parsed['extensions']['subjectAltName'] ?? '') !== 'DNS:' . $host ||
            $parsed['validFrom_time_t'] > time() || $parsed['validTo_time_t'] <= time()) {
            throw new RuntimeException('Native certificate does not match the verified key and host');
        }
        $portText = (string)$root->system->webgui->port;
        $port = $portText === '' ? 443 : (ctype_digit($portText) ? (int)$portText : 0);
        if ($port < 1 || $port > 65535) {
            throw new RuntimeException('Invalid native GUI port');
        }
        $after = new SimpleXMLElement('<cert/>');
        foreach (['refid' => $ref, 'descr' => $description, 'crt' => base64_encode($chain), 'prv' => base64_encode($pem)] as $field => $text) {
            $after->addChild($field, $text);
        }
        $snapshot = ['version' => 1, 'nonce' => $request['nonce'], 'candidate_sha256' => $request['candidate_sha256'],
            'device_id' => $device, 'generation' => $issued['generation'], 'generation_id' => $issued['generation_id'],
            'host' => $host, 'leaf_fingerprint' => $issued['leaf_fingerprint'], 'port' => $port, 'refid' => $ref,
            'before_ref' => $beforeRef, 'before_selected_hash' => $this->hash($this->cert($root, $beforeRef)),
            'before_xml' => $before === null ? null : $before->asXML(), 'after_xml' => $after->asXML()];
        return ['refid' => $ref, 'native_hash' => $this->hash($after), 'port' => $port,
            'snapshot_sha256' => $this->writeSnapshot($request['nonce'], $snapshot)];
    }

    private function transaction(array $request, array $phases): array
    {
        $value = $this->journal();
        if ($value === null || !in_array($value['phase'] ?? '', $phases, true)) {
            throw new RuntimeException('Native transaction phase differs');
        }
        foreach (['nonce' => 32, 'snapshot_sha256' => 64, 'candidate_sha256' => 64] as $field => $length) {
            if (!is_string($request[$field] ?? null) || !preg_match('/\A[a-f0-9]{' . $length . '}\z/D', $request[$field]) ||
                ($value[$field] ?? null) !== $request[$field]) {
                throw new RuntimeException('Native transaction identity differs');
            }
        }
        $raw = $this->read($this->directory . '/snapshot-' . $value['nonce'] . '.json', 1048576);
        if (!hash_equals($value['snapshot_sha256'], hash('sha256', $raw))) {
            throw new RuntimeException('Private native snapshot changed');
        }
        $snapshot = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        foreach (['nonce', 'candidate_sha256', 'device_id', 'generation', 'generation_id', 'refid', 'port'] as $field) {
            if (($value[$field] ?? null) !== ($snapshot[$field] ?? null)) {
                throw new RuntimeException('Native snapshot binding differs');
            }
        }
        $after = $this->node($snapshot['after_xml']);
        $before = $snapshot['before_xml'] === null ? null : $this->node($snapshot['before_xml']);
        $description = 'NetHub managed GUI ' . $snapshot['device_id'];
        if (($snapshot['version'] ?? null) !== 1 || !preg_match('/\A[a-f0-9]{13}\z/D', $snapshot['refid']) ||
            (string)$after->refid !== $snapshot['refid'] || (string)$after->descr !== $description ||
            $this->hash($after) !== ($value['native_hash'] ?? null) || $before !== null && (
                (string)$before->refid !== $snapshot['refid'] || (string)$before->descr !== $description)) {
            throw new RuntimeException('Native snapshot entry differs');
        }
        return $snapshot;
    }

    public function dispatch(string $action, array $request): array
    {
        if (!in_array($action, ['prepare', 'install', 'check', 'rollback'], true)) {
            throw new RuntimeException('Unknown native certificate operation');
        }
        $this->configuration->lock();
        try {
            $root = $this->configuration->object();
            if ($action === 'prepare') {
                return $this->prepare($root, $request);
            }
            $snapshot = $this->transaction($request, $action === 'install' ? ['prepared'] :
                ($action === 'rollback' ? ['prepared', 'written'] : ['prepared', 'written', 'applied']));
            $ref = $snapshot['refid'];
            $beforeHash = $snapshot['before_xml'] === null ? null : $this->hash($this->node($snapshot['before_xml']));
            $afterHash = $this->hash($this->node($snapshot['after_xml']));
            $currentHash = $this->hash($this->cert($root, $ref));
            $selected = $this->selected($root);
            $after = $selected === $ref && $currentHash === $afterHash;
            $before = $selected === $snapshot['before_ref'] && $currentHash === $beforeHash;
            if ($action === 'check') {
                if (!$after) {
                    throw new RuntimeException('Native applied selection differs');
                }
                return ['selected' => true, 'host' => $snapshot['host'], 'port' => $snapshot['port'],
                    'leaf_fingerprint' => $snapshot['leaf_fingerprint']];
            }
            if ($action === 'install') {
                $this->active($root, $snapshot);
                if (!$before && !$after) {
                    throw new RuntimeException('Native configuration changed before installation');
                }
                if (!$after) {
                    $this->replace($root, $ref, $snapshot['after_xml']);
                    $root->system->webgui->{'ssl-certref'} = $ref;
                    $this->save();
                }
                return ['selected' => true, 'changed' => !$after];
            }
            if (!$before && !$after) {
                throw new RuntimeException('Native configuration changed before rollback');
            }
            if ($after && !$before) {
                if ($snapshot['before_ref'] !== $ref &&
                    $this->hash($this->cert($root, $snapshot['before_ref'])) !== $snapshot['before_selected_hash']) {
                    throw new RuntimeException('Previous native GUI certificate was changed');
                }
                $this->replace($root, $ref, $snapshot['before_xml']);
                $root->system->webgui->{'ssl-certref'} = $snapshot['before_ref'];
                $this->save();
            }
            return ['restored' => true, 'changed' => $after && !$before];
        } finally {
            $this->configuration->unlock();
        }
    }
}
