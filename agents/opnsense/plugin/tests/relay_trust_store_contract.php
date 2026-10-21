<?php

// The real writer runs only against a marked temporary XML model in this fixture.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (): never { throw new RuntimeException('Native trust fixture warning'); });

final class TrustFixtureConfig
{
    private $stream;
    public SimpleXMLElement $root;
    public bool $locked = false;
    public function __construct(private string $path, private string $fault) {}
    public function lock(): void
    {
        $this->stream = fopen($this->path, 'r+b');
        if (!flock($this->stream, LOCK_EX)) { throw new RuntimeException('Fixture lock failed'); }
        $this->root = simplexml_load_string(stream_get_contents($this->stream), SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOBLANKS);
        $this->locked = true;
    }
    public function save(array $description): void
    {
        if ($this->fault === 'drop') { return; }
        rewind($this->stream);
        if (!ftruncate($this->stream, 0) || fwrite($this->stream, $this->root->asXML()) === false || !fflush($this->stream)) {
            throw new RuntimeException('Fixture save failed');
        }
        if ($this->fault === 'lost_reply') { throw new RuntimeException('Fixture save reply lost'); }
    }
    public function unlock(): void
    {
        $this->locked = false;
        flock($this->stream, LOCK_UN);
        fclose($this->stream);
    }
}

final class TrustFixtureModel
{
    private array $pending = [];
    public function __construct(private TrustFixtureConfig $configuration, private bool $invalid)
    {
        if (!$configuration->locked) { throw new RuntimeException('Model constructed outside native lock'); }
    }
    public function __get(string $key): string { return (string)$this->configuration->root->OPNsense->NetHubAgent->$key; }
    public function setNodes(array $values): void { $this->pending = $values; }
    public function performValidation(): array { return $this->invalid ? ['invalid'] : []; }
    public function serializeToConfig(): void
    {
        foreach ($this->pending as $key => $value) { $this->configuration->root->OPNsense->NetHubAgent->$key = $value; }
    }
}

try {
    $input = json_decode(stream_get_contents(STDIN, 140000), true, 32, JSON_THROW_ON_ERROR);
    $parent = realpath(dirname($input['config_file']));
    $temporary = realpath(sys_get_temp_dir());
    if ($parent === false || $temporary === false || !str_starts_with($parent, $temporary . '/') ||
        basename($input['config_file']) !== 'native-config.xml' ||
        file_get_contents($parent . '/fenced-native-trust-fixture') !== 'fixture-only' ||
        dirname($input['state_directory']) !== $parent) {
        throw new RuntimeException('A marked temporary trust fixture is required');
    }
    require $argv[1];
    $config = new TrustFixtureConfig($input['config_file'], $input['fault'] ?? '');
    $invalid = ($input['fault'] ?? '') === 'validation';
    $store = new NativeRelayTrustStore($config, static fn() => new TrustFixtureModel($config, $invalid),
        $input['config_file'], $input['state_directory'], $input['config_identity'], $input['owner']);
    echo json_encode(['success' => true, 'result' => $store->dispatch($input['action'], $input['request'])], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    echo json_encode(['success' => false, 'message' => 'Fenced native trust model refused the operation'], JSON_THROW_ON_ERROR);
    exit(1);
}
