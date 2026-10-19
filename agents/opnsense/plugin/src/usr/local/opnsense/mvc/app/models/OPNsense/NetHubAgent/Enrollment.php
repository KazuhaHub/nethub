<?php

namespace OPNsense\NetHubAgent;

final class Enrollment
{
    private static function matches($pattern, $value)
    {
        return is_string($value) && preg_match($pattern, $value) === 1;
    }

    private static function hostname($value)
    {
        return is_string($value) && strlen($value) <= 253 && self::matches(
            '/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/D',
            $value
        );
    }

    private static function decode($value)
    {
        if (!self::matches('/^[A-Za-z0-9_-]+$/D', $value)) {
            return false;
        }
        $raw = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        return $raw !== false && rtrim(strtr(base64_encode($raw), '+/', '-_'), '=') === $value ? $raw : false;
    }

    public static function token($value)
    {
        return is_string($value) && strlen($value) === 43 && strlen(self::decode($value) ?: '') === 32;
    }

    public static function origin($value)
    {
        if (!self::matches('/^https:\/\/[!-~]{1,504}$/D', $value) || strpbrk($value, "\\?#") !== false) {
            return null;
        }
        $parts = parse_url($value);
        if (
            $parts === false || isset($parts['user']) || isset($parts['pass']) ||
            !isset($parts['host']) || !in_array($parts['path'] ?? '', ['', '/'], true) ||
            isset($parts['port']) && ($parts['port'] < 1 || $parts['port'] > 65535)
        ) {
            return null;
        }
        $host = strtolower($parts['host']);
        if (!self::hostname($host) && filter_var(trim($host, '[]'), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return null;
        }
        $authority = $host . (isset($parts['port']) ? ':' . $parts['port'] : '');
        return strtolower(rtrim(substr($value, 8), '/')) === $authority ? 'https://' . $authority : null;
    }

    public static function ca($value)
    {
        if (!is_string($value) || strlen($value) > 32768) {
            return false;
        }
        preg_match_all('/-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+\/=\r\n]+-----END CERTIFICATE-----\n/', $value, $blocks);
        if (count($blocks[0]) < 1 || count($blocks[0]) > 2 || implode('', $blocks[0]) !== $value) {
            return false;
        }
        $seen = [];
        foreach ($blocks[0] as $block) {
            $certificate = @openssl_x509_parse($block);
            $digest = @openssl_x509_fingerprint($block, 'sha256');
            if (
                $certificate === false || $digest === false || isset($seen[$digest]) ||
                !str_contains($certificate['extensions']['basicConstraints'] ?? '', 'CA:TRUE') ||
                !isset($certificate['validFrom_time_t'], $certificate['validTo_time_t']) ||
                $certificate['validFrom_time_t'] > time() || $certificate['validTo_time_t'] <= time()
            ) {
                return false;
            }
            $seen[$digest] = true;
        }
        return true;
    }

    private static function timestamp($value)
    {
        if (!self::matches('/^(?!0000)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}(?:Z|[+-]\d\d:\d\d)$/D', $value)) {
            return false;
        }
        $instant = @date_create_immutable($value);
        $errors = \DateTimeImmutable::getLastErrors();
        return $instant !== false && ($errors === false || $errors['warning_count'] + $errors['error_count'] === 0);
    }

    public static function assignment($value)
    {
        $fields = ['agent_protocol_version', 'device_id', 'device_secret', 'frp_token', 'server_addr',
                   'server_port', 'server_name', 'subdomain', 'domain_claim', 'relay_ca_pem'];
        if (!is_array($value) || count($value) > 26 || array_diff($fields, array_keys($value))) {
            return null;
        }
        $uuid = '/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/D';
        $version = '/^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/D';
        if (
            !self::matches($version, $value['agent_protocol_version']) || strlen($value['agent_protocol_version']) > 64 ||
            !self::matches($uuid, $value['device_id']) || !self::token($value['device_secret']) ||
            !self::matches('/^[a-f0-9]{64}$/D', $value['frp_token']) ||
            !self::hostname($value['server_name']) ||
            (!self::hostname($value['server_addr']) && filter_var($value['server_addr'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) ||
            !is_int($value['server_port']) || $value['server_port'] < 1 || $value['server_port'] > 65535 ||
            !self::matches('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $value['subdomain']) ||
            !is_string($value['domain_claim']) || strlen($value['domain_claim']) > 3116 || !self::ca($value['relay_ca_pem'])
        ) {
            return null;
        }
        $parts = explode('.', $value['domain_claim']);
        if (count($parts) !== 2 || !self::token($parts[1])) {
            return null;
        }
        $decoded = self::decode($parts[0]);
        $claim = $decoded === false ? null : json_decode($decoded, true, 8);
        if (
            !is_array($claim) || count($claim) !== 5 ||
            array_diff(['device_id', 'tenant_id', 'subdomain', 'issued_at', 'key_id'], array_keys($claim)) ||
            $claim['device_id'] !== $value['device_id'] || $claim['subdomain'] !== $value['subdomain'] ||
            !self::matches($uuid, $claim['tenant_id']) ||
            !self::matches('/^[a-z0-9][a-z0-9_-]{0,31}$/D', $claim['key_id']) ||
            !self::timestamp($claim['issued_at'])
        ) {
            return null;
        }
        // The verified console authenticated this assignment; the agent does not hold the claim signing key.
        return array_intersect_key($value, array_flip($fields));
    }
}
