<?php

// This adapter writes only a marked temporary fixture, never the host config.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_error_handler(static function (): never {
    throw new RuntimeException('Native model warning');
});

final class NativeCertificateFixtureConfig
{
    private $stream;
    private SimpleXMLElement $root;

    public function __construct(private string $path)
    {
    }

    public function lock(): void
    {
        $this->stream = fopen($this->path, 'r+b');
        if (!flock($this->stream, LOCK_EX)) {
            throw new RuntimeException('Fixture lock failed');
        }
        rewind($this->stream);
        $this->root = simplexml_load_string(stream_get_contents($this->stream), SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOBLANKS);
    }

    public function object(): SimpleXMLElement
    {
        return $this->root;
    }

    public function save(?array $revision = null): void
    {
        rewind($this->stream);
        if (!ftruncate($this->stream, 0) || fwrite($this->stream, $this->root->asXML()) === false || !fflush($this->stream)) {
            throw new RuntimeException('Fixture save failed');
        }
    }

    public function unlock(): void
    {
        flock($this->stream, LOCK_UN);
        fclose($this->stream);
    }
}

try {
    $input = json_decode(stream_get_contents(STDIN, 16385), true, 32, JSON_THROW_ON_ERROR);
    $parent = realpath(dirname($input['config_file']));
    $temporary = realpath(sys_get_temp_dir());
    if ($parent === false || $temporary === false || !str_starts_with($parent, $temporary . '/') ||
        basename($input['config_file']) !== 'native-config.xml' ||
        file_get_contents($parent . '/fenced-native-store-fixture') !== 'fixture-only' ||
        dirname($input['directory']) !== $parent || dirname($input['state_directory']) !== $parent) {
        throw new RuntimeException('A marked temporary fixture is required');
    }
    require $argv[1];
    $store = new NativeGuiCertificateStore(new NativeCertificateFixtureConfig($input['config_file']),
        $input['directory'], $input['config_file'], $input['state_directory'], $input['owner'], $input['config_identity'] ?? null);
    echo json_encode(['success' => true, 'result' => $store->dispatch($input['action'], $input['request'])], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    echo json_encode(['success' => false, 'message' => 'Fenced native certificate model refused the operation',
        'error_type' => get_class($error), 'error_line' => $error->getLine()], JSON_THROW_ON_ERROR);
    exit(1);
}
