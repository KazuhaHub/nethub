<?php

/** Native model CAS boundary; the caller holds reconcile.lock and verifies trust. */
final class NativeRelayTrustStore
{
    private const NODES = ['relay_ca', 'relay_trust_state'];
    private const BINDING = ['console_url', 'device_id', 'device_secret', 'domain_claim', 'frp_token',
                             'server_addr', 'server_name', 'server_port', 'subdomain'];

    public function __construct(
        private object $configuration,
        private Closure $models,
        private string $configFile,
        private string $stateDirectory,
        private array $configIdentity,
        private int $owner = 0
    )
    {
        $resolved = realpath($configFile);
        if ($resolved === false || array_keys($configIdentity) !== ['uid', 'gid'] ||
            !is_int($configIdentity['uid']) || !is_int($configIdentity['gid']) ||
            $configIdentity['uid'] < 0 || $configIdentity['gid'] < 0) {
            throw new RuntimeException('Invalid native trust configuration identity');
        }
        $this->configFile = $resolved;
        $this->protectConfiguration();
    }

    private function protectConfiguration(): void
    {
        clearstatcache(true, $this->configFile);
        $info = lstat($this->configFile);
        if ($info === false || ($info['mode'] & 0170000) !== 0100000 || $info['nlink'] !== 1 ||
            !in_array($info['uid'], [$this->owner, $this->configIdentity['uid']], true) ||
            $info['gid'] !== $this->configIdentity['gid'] || !in_array($info['mode'] & 0777, [0600, 0640], true) ||
            realpath($this->configFile) !== $this->configFile) {
            throw new RuntimeException('Native trust configuration needs local review');
        }
    }

    private static function encoded(array $value): string
    {
        ksort($value);
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    }

    private static function decode(string $value, int $maximum): string
    {
        $decoded = base64_decode($value, true);
        if ($decoded === false || strlen($decoded) > $maximum || base64_encode($decoded) !== $value) {
            throw new RuntimeException('Invalid native trust encoding');
        }
        return $decoded;
    }

    private static function nodes(mixed $value, string $name, bool $candidate): ?array
    {
        if (!is_array($value) || array_keys($value) !== self::NODES ||
            !is_string($value['relay_ca']) || !is_string($value['relay_trust_state'])) {
            throw new RuntimeException('Invalid native trust nodes');
        }
        $pem = self::decode($value['relay_ca'], 32768);
        if (strlen($pem) < 64) {
            throw new RuntimeException('Missing native relay trust');
        }
        if ($value['relay_trust_state'] === '') {
            if ($candidate) {
                throw new RuntimeException('A candidate requires a generation');
            }
            return null;
        }
        $raw = self::decode($value['relay_trust_state'], 4096);
        $state = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        $fields = ['bundle_fingerprint', 'generation', 'generation_id', 'not_before', 'published_at', 'server_name', 'valid_until'];
        if (!is_array($state) || array_keys($state) !== $fields || self::encoded($state) !== $raw ||
            !is_int($state['generation']) || $state['generation'] < 1 || $state['generation'] > 2147483647 ||
            !is_string($state['generation_id']) || !preg_match('/\A[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\z/D', $state['generation_id']) ||
            $state['generation_id'] === '00000000-0000-0000-0000-000000000000' ||
            $state['server_name'] !== $name || !is_string($state['bundle_fingerprint']) ||
            !hash_equals(hash('sha256', 'nethub-relay-trust-v1:' . $pem), $state['bundle_fingerprint'])) {
            throw new RuntimeException('Invalid native trust generation');
        }
        foreach (['not_before', 'published_at', 'valid_until'] as $field) {
            if (!is_string($state[$field]) || !preg_match('/\A(?!0000)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z\z/D', $state[$field])) {
                throw new RuntimeException('Invalid native trust timestamp');
            }
            $instant = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s.u\Z', $state[$field], new DateTimeZone('UTC'));
            if ($instant === false || $instant->format('Y-m-d\TH:i:s.u\Z') !== $state[$field]) {
                throw new RuntimeException('Invalid native trust timestamp');
            }
        }
        if ($state['not_before'] >= $state['valid_until'] || $state['published_at'] < $state['not_before'] ||
            $state['published_at'] >= $state['valid_until']) {
            throw new RuntimeException('Invalid native trust validity');
        }
        return $state;
    }

    private function active(object $model): void
    {
        clearstatcache(true, $this->stateDirectory);
        $info = lstat($this->stateDirectory);
        if ($info === false || ($info['mode'] & 0170000) !== 0040000 || $info['uid'] !== $this->owner ||
            ($info['mode'] & 0777) !== 0700 || realpath($this->stateDirectory) !== $this->stateDirectory ||
            (string)$model->enabled !== '1') {
            throw new RuntimeException('Native trust application is inactive');
        }
        foreach (['disabled', 'stopped', 'revoked', 'uninstalling'] as $marker) {
            if (file_exists($this->stateDirectory . '/' . $marker) || is_link($this->stateDirectory . '/' . $marker)) {
                throw new RuntimeException('Native trust application is inactive');
            }
        }
    }

    private function flush(array $target, string $binding): void
    {
        $this->protectConfiguration();
        $stream = fopen($this->configFile, 'r+b');
        try {
            if (!fsync($stream)) {
                throw new RuntimeException('Native trust configuration flush failed');
            }
            rewind($stream);
            $raw = stream_get_contents($stream, 16777217);
            if ($raw === false || strlen($raw) > 16777216 || stripos($raw, '<!DOCTYPE') !== false) {
                throw new RuntimeException('Native trust readback exceeds its limit');
            }
            $xml = simplexml_load_string($raw, SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOBLANKS);
            if ($xml === false) { throw new RuntimeException('Native trust readback failed'); }
            $model = $xml->OPNsense->NetHubAgent;
            $identity = [];
            foreach (self::BINDING as $key) { $identity[$key] = (string)$model->$key; }
            foreach (self::NODES as $key) {
                if ((string)$model->$key !== $target[$key]) { throw new RuntimeException('Native trust save was not confirmed'); }
            }
            if (!hash_equals($binding, hash('sha256', self::encoded($identity)))) {
                throw new RuntimeException('Native enrollment changed during save');
            }
        } finally { fclose($stream); }
    }

    public function dispatch(string $action, array $request): array
    {
        if (!in_array($action, ['read', 'install', 'rollback'], true) ||
            ($action === 'read' && $request !== []) ||
            ($action !== 'read' && array_keys($request) !== ['binding', 'before', 'after'])) {
            throw new RuntimeException('Invalid native trust operation');
        }
        $this->configuration->lock();
        try {
            $this->protectConfiguration();
            $model = ($this->models)();
            $identity = [];
            foreach (self::BINDING as $key) { $identity[$key] = (string)$model->$key; }
            if ($identity['device_id'] === '' || $identity['device_secret'] === '' || $identity['server_name'] === '') {
                throw new RuntimeException('Native enrollment is unavailable');
            }
            $binding = hash('sha256', self::encoded($identity));
            $current = [];
            foreach (self::NODES as $key) { $current[$key] = (string)$model->$key; }
            if ($action === 'read') {
                return ['binding' => $binding, 'device_id' => $identity['device_id'],
                        'server_name' => $identity['server_name'], 'nodes' => $current];
            }
            if (!is_string($request['binding']) || !hash_equals($binding, $request['binding'])) {
                throw new RuntimeException('Native enrollment changed');
            }
            $before = self::nodes($request['before'], $identity['server_name'], false);
            $after = self::nodes($request['after'], $identity['server_name'], true);
            if ($before !== null && ($after['generation'] < $before['generation'] ||
                ($after['generation'] === $before['generation'] && $request['before'] !== $request['after']) ||
                ($after['generation'] > $before['generation'] && $after['generation_id'] === $before['generation_id']))) {
                throw new RuntimeException('Native trust generation regressed');
            }
            if ($current !== $request['before'] && $current !== $request['after']) {
                throw new RuntimeException('Native trust changed outside this operation');
            }
            $target = $action === 'install' ? $request['after'] : $request['before'];
            if ($action === 'install') { $this->active($model); }
            $changed = $current !== $target;
            if ($changed) {
                $model->setNodes($target);
                if (count($model->performValidation()) !== 0) {
                    throw new RuntimeException('Native model validation refused trust');
                }
                $model->serializeToConfig();
                $this->configuration->save(['description' => 'NetHub relay trust configuration']);
            }
            // An exact retry also flushes a save whose original response was lost.
            $this->flush($target, $binding);
            return ['selected' => true, 'changed' => $changed];
        } finally { $this->configuration->unlock(); }
    }
}
