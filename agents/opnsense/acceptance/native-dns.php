<?php

// Disposable console DNS provisioning; never installed in the plugin.
function configure_fixture_console_dns($model, string $nonce): void
{
    if (!preg_match('/\A[a-f0-9]{32}\z/D', $nonce) || (string)$model->general->enabled !== '1') {
        throw new RuntimeException('Enabled native resolver required');
    }
    foreach ($model->hosts->host->iterateItems() as $item) {
        if (in_array(strtolower((string)$item->hostname), ['console', '*'], true) &&
            strcasecmp((string)$item->domain, 'example.com') === 0) {
            throw new RuntimeException('Console override already exists');
        }
    }
    $item = $model->hosts->host->add();
    foreach (['enabled' => '1', 'hostname' => 'console', 'domain' => 'example.com',
              'rr' => 'A', 'server' => '10.0.2.100', 'addptr' => '0',
              'description' => 'NetHub isolated console ' . $nonce] as $field => $value) {
        $item->$field->setValue($value);
    }
    if (count($model->performValidation()) !== 0) {
        throw new RuntimeException('Native console DNS model invalid');
    }
}
