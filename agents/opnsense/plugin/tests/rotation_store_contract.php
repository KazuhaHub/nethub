<?php

require $argv[1];
require $argv[2];
$fixture = json_decode(file_get_contents($argv[3]), true, 16, JSON_THROW_ON_ERROR);
$directory = $argv[4];
mkdir($directory, 0700);
$file = $directory . '/config.xml';
$original = [];
foreach (NativeRotationStore::FIELDS as $field) { $original[$field] = (string)($fixture[$field] ?? ''); }
$original['console_url'] = 'https://console.example.com';
$original['relay_ca'] = base64_encode($fixture['relay_ca_pem']);
$original['enabled'] = '0';
$original['unrelated'] = 'retained';
$GLOBALS['nodes'] = $original;
$GLOBALS['events'] = [];
function persistFixture(): void {
    global $file;
    $xml = new SimpleXMLElement('<opnsense><OPNsense><NetHubAgent/></OPNsense></opnsense>');
    foreach ($GLOBALS['nodes'] as $key => $value) { $xml->OPNsense->NetHubAgent->addChild($key, htmlspecialchars($value, ENT_XML1)); }
    file_put_contents($file, $xml->asXML());
    chmod($file, 0600);
}
persistFixture();
$configuration = new class {
    public function lock() { $GLOBALS['events'][] = 'lock'; }
    public function unlock() { $GLOBALS['events'][] = 'unlock'; }
    public function save($revision) { $GLOBALS['events'][] = 'save'; persistFixture(); }
};
$models = static function () {
    if (end($GLOBALS['events']) !== 'lock') { throw new RuntimeException('model created before native lock'); }
    return new class {
        private array $nodes;
        public function __construct() { $this->nodes = $GLOBALS['nodes']; }
        public function __get($key) { return $this->nodes[$key]; }
        public function setNodes($nodes) { foreach ($nodes as $key => $value) { $this->nodes[$key] = $value; } }
        public function performValidation() { return []; }
        public function serializeToConfig() { $GLOBALS['nodes'] = $this->nodes; }
    };
};
$uid = fileowner($file);
$identity = ['uid' => $uid, 'gid' => filegroup($file)];
$store = new NativeRotationStore($configuration, $models, $file, $identity, $directory, $uid);
$before = $store->dispatch('read', [])['nodes'];
$after = $before;
$after['device_secret'] = str_repeat('B', 42) . 'A';
$parts = explode('.', $after['domain_claim']);
$payload = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true, 8, JSON_THROW_ON_ERROR);
$payload['issued_at'] = '2026-10-28T00:00:00.000001Z';
$after['domain_claim'] = rtrim(strtr(base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)), '+/', '-_'), '=') . '.' . $parts[1];
$request = ['before' => $before, 'after' => $after];
// Operator stop/circuit policy remains in place; credential replacement does not start services.
file_put_contents($directory . '/disabled', '');
$first = $store->dispatch('install', $request);
if ($first !== ['selected' => true, 'changed' => true] || $GLOBALS['nodes']['enabled'] !== '0' ||
    $GLOBALS['nodes']['unrelated'] !== 'retained' || !file_exists($directory . '/disabled')) { exit(10); }
$retry = $store->dispatch('install', $request);
if ($retry !== ['selected' => true, 'changed' => false] || count(array_filter($GLOBALS['events'], static fn($event) => $event === 'save')) !== 1) { exit(11); }
foreach (['enabled', 'device_id', 'console_url', 'relay_trust_state'] as $field) {
    $bad = $request;
    $bad['after'][$field] = $field === 'enabled' ? '1' : 'changed';
    try { $store->dispatch('install', $bad); exit(12); } catch (RuntimeException $error) {}
}
file_put_contents($directory . '/revoked', '');
try { $store->dispatch('install', $request); exit(13); } catch (RuntimeException $error) {}
if (end($GLOBALS['events']) !== 'unlock') { exit(14); }
echo json_encode(['stable_policy' => true, 'single_save' => true, 'readback' => true,
    'conflicts_refused' => true, 'revoked_refused' => true], JSON_THROW_ON_ERROR);
