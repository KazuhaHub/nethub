<?php

/** Native credential CAS; the root caller holds reconcile.lock throughout. */
final class NativeRotationStore
{
    public const FIELDS = ['console_url', 'device_id', 'device_secret', 'frp_token', 'server_addr',
        'server_port', 'server_name', 'subdomain', 'domain_claim', 'relay_ca', 'relay_trust_state', 'enabled'];
    private const MUTABLE = ['device_secret', 'frp_token', 'server_addr', 'server_port', 'server_name', 'domain_claim'];

    public function __construct(
        private object $configuration,
        private Closure $models,
        private string $configFile,
        private array $configIdentity,
        private string $stateDirectory,
        private int $owner = 0
    ) {
        $resolved = realpath($configFile);
        if ($resolved === false || array_keys($configIdentity) !== ['uid', 'gid'] ||
            !is_int($configIdentity['uid']) || !is_int($configIdentity['gid'])) {
            throw new RuntimeException('Invalid native rotation identity');
        }
        $this->configFile = $resolved;
        $this->protect();
    }

    private function protect(): void
    {
        clearstatcache(true, $this->configFile);
        $info = lstat($this->configFile);
        if ($info === false || ($info['mode'] & 0170000) !== 0100000 || $info['nlink'] !== 1 ||
            !in_array($info['uid'], [$this->owner, $this->configIdentity['uid']], true) ||
            $info['gid'] !== $this->configIdentity['gid'] || !in_array($info['mode'] & 0777, [0600, 0640], true) ||
            realpath($this->configFile) !== $this->configFile) {
            throw new RuntimeException('Native rotation configuration needs local review');
        }
        $state = lstat($this->stateDirectory);
        if ($state === false || ($state['mode'] & 0170000) !== 0040000 || $state['uid'] !== $this->owner ||
            ($state['mode'] & 0777) !== 0700 || realpath($this->stateDirectory) !== $this->stateDirectory) {
            throw new RuntimeException('Native rotation storage needs local review');
        }
    }

    private static function snapshot(object $model): array
    {
        $nodes = [];
        foreach (self::FIELDS as $field) { $nodes[$field] = (string)$model->$field; }
        return $nodes;
    }

    private static function validate(mixed $nodes): array
    {
        if (!is_array($nodes) || array_keys($nodes) !== self::FIELDS ||
            array_filter($nodes, static fn($value) => !is_string($value)) ||
            !in_array($nodes['enabled'], ['0', '1'], true) ||
            \OPNsense\NetHubAgent\Enrollment::origin($nodes['console_url']) !== $nodes['console_url'] ||
            !preg_match('/\A[1-9][0-9]{0,4}\z/D', $nodes['server_port'])) {
            throw new RuntimeException('Invalid native rotation nodes');
        }
        $pem = base64_decode($nodes['relay_ca'], true);
        if ($pem === false || base64_encode($pem) !== $nodes['relay_ca']) {
            throw new RuntimeException('Invalid native rotation trust');
        }
        $assignment = $nodes;
        $assignment['agent_protocol_version'] = '1.6.0';
        $assignment['server_port'] = (int)$nodes['server_port'];
        $assignment['relay_ca_pem'] = $pem;
        if (\OPNsense\NetHubAgent\Enrollment::assignment($assignment) === null) {
            throw new RuntimeException('Invalid native rotation assignment');
        }
        return $nodes;
    }

    private function flush(array $target): void
    {
        $this->protect();
        $stream = fopen($this->configFile, 'r+b');
        try {
            if (!fsync($stream)) { throw new RuntimeException('Native rotation flush failed'); }
            rewind($stream);
            $raw = stream_get_contents($stream, 16777217);
            if ($raw === false || strlen($raw) > 16777216 || stripos($raw, '<!DOCTYPE') !== false) {
                throw new RuntimeException('Invalid native rotation readback');
            }
            $xml = simplexml_load_string($raw, SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOBLANKS);
            if ($xml === false || self::snapshot($xml->OPNsense->NetHubAgent) !== $target) {
                throw new RuntimeException('Native rotation save was not confirmed');
            }
        } finally { fclose($stream); }
    }

    private static function claim(string $value): array
    {
        $payload = explode('.', $value)[0];
        $raw = base64_decode(strtr($payload, '-_', '+/') . str_repeat('=', (4 - strlen($payload) % 4) % 4), true);
        $result = $raw === false ? null : json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($result)) { throw new RuntimeException('Invalid native claim'); }
        return $result;
    }

    public function dispatch(string $action, array $request): array
    {
        if (!in_array($action, ['read', 'install'], true) || ($action === 'read' && $request !== []) ||
            ($action === 'install' && array_keys($request) !== ['before', 'after'])) {
            throw new RuntimeException('Invalid native rotation operation');
        }
        $this->configuration->lock();
        try {
            $this->protect();
            // Construct after native lock acquisition/reload, never from stale XML.
            $model = ($this->models)();
            $current = self::validate(self::snapshot($model));
            if ($action === 'read') { return ['nodes' => $current]; }
            $before = self::validate($request['before']);
            $after = self::validate($request['after']);
            foreach (self::FIELDS as $field) {
                if (!in_array($field, self::MUTABLE, true) && $before[$field] !== $after[$field]) {
                    throw new RuntimeException('Rotation cannot change native identity or local policy');
                }
            }
            if ($before['device_secret'] === $after['device_secret'] ||
                $before['domain_claim'] === $after['domain_claim'] || ($current !== $before && $current !== $after)) {
                throw new RuntimeException('Native rotation changed outside this operation');
            }
            if ($before['relay_trust_state'] !== '' && $before['server_name'] !== $after['server_name']) {
                throw new RuntimeException('Managed relay trust must be updated separately');
            }
            $oldClaim = self::claim($before['domain_claim']);
            $newClaim = self::claim($after['domain_claim']);
            foreach (['device_id', 'tenant_id', 'subdomain'] as $field) {
                if ($oldClaim[$field] !== $newClaim[$field]) { throw new RuntimeException('Native claim identity changed'); }
            }
            if (new DateTimeImmutable($newClaim['issued_at']) <= new DateTimeImmutable($oldClaim['issued_at'])) {
                throw new RuntimeException('Native claim issuance did not advance');
            }
            foreach (['revoked', 'uninstalling'] as $marker) {
                if (file_exists($this->stateDirectory . '/' . $marker) || is_link($this->stateDirectory . '/' . $marker)) {
                    throw new RuntimeException('Native rotation is unavailable');
                }
            }
            $changed = $current !== $after;
            if ($changed) {
                $nodes = array_intersect_key($after, array_flip(self::MUTABLE));
                $model->setNodes($nodes);
                if (count($model->performValidation()) !== 0) {
                    throw new RuntimeException('Native model refused rotation');
                }
                $model->serializeToConfig();
                $this->configuration->save(['description' => 'NetHub device credentials rotated']);
            }
            $this->flush($after);
            return ['selected' => true, 'changed' => $changed];
        } finally { $this->configuration->unlock(); }
    }
}
