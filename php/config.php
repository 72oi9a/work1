<?php
declare(strict_types=1);

function env_value(string $name, ?string $default = null): ?string
{
    $value = getenv($name);
    if ($value !== false && $value !== '') return $value;

    $envFile = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.env';
    if (is_readable($envFile)) {
        foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            [$key, $raw] = array_pad(explode('=', $line, 2), 2, '');
            if (trim($key) === $name) return trim($raw, " \t\"'");
        }
    }
    return $default;
}

function db(): PDO
{
    static $pdo;
    if ($pdo instanceof PDO) return $pdo;

    $url = env_value('DATABASE_URL');
    if (!$url) throw new RuntimeException('DATABASE_URL is not configured');
    $parts = parse_url($url);
    if (!$parts || empty($parts['host']) || empty($parts['path'])) {
        throw new RuntimeException('DATABASE_URL is invalid');
    }

    $dsn = 'pgsql:host=' . $parts['host'] . ';port=' . ($parts['port'] ?? 5432) . ';dbname=' . ltrim($parts['path'], '/');
    $pdo = new PDO($dsn, urldecode($parts['user'] ?? ''), urldecode($parts['pass'] ?? ''), [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function request_json(): array
{
    $raw = file_get_contents('php://input') ?: '';
    if ($raw === '') return $_POST ?: [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function input_string(array $input, string $key, ?string $default = null): ?string
{
    if (!array_key_exists($key, $input) || $input[$key] === null) return $default;
    return is_scalar($input[$key]) ? trim((string) $input[$key]) : $default;
}

function nullable_string(array $input, string $key): ?string
{
    $value = input_string($input, $key);
    return $value === '' ? null : $value;
}
