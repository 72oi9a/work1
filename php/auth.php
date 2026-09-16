<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';

const SESSION_COOKIE = 'scout_session';
const PAGE_KEYS = ['dashboard', 'official-forms', 'members', 'supervisors', 'reports', 'settings'];

function hash_session_token(string $token): string { return hash('sha256', $token); }

function scrypt_binary(string $password, string $salt, int $n = 16384, int $r = 8, int $p = 1): string
{
    if ($n < 2 || ($n & ($n - 1)) !== 0) throw new InvalidArgumentException('Invalid scrypt cost');
    $block = hash_pbkdf2('sha256', $password, $salt, 1, 128 * $r * $n, true);
    $chunk = 128 * $r;
    $out = '';
    for ($i = 0; $i < $p; $i++) $out .= scrypt_romix(substr($block, $i * $chunk, $chunk), $n, $r);
    return hash_pbkdf2('sha256', $password, $out, 1, 64, true);
}

function scrypt_romix(string $input, int $n, int $r): string
{
    $x = $input;
    $v = [];
    for ($i = 0; $i < $n; $i++) { $v[$i] = $x; $x = scrypt_block_mix($x, $r); }
    for ($i = 0; $i < $n; $i++) {
        $index = scrypt_little_endian(substr($x, -64, 4)) & ($n - 1);
        $x = scrypt_block_mix($x ^ $v[$index], $r);
    }
    return $x;
}

function scrypt_block_mix(string $block, int $r): string
{
    $x = substr($block, -64);
    $out = [];
    for ($i = 0; $i < 2 * $r; $i++) {
        $x = scrypt_salsa8($x ^ substr($block, $i * 64, 64));
        $out[$i] = $x;
    }
    $result = '';
    for ($i = 0; $i < $r; $i++) $result .= $out[2 * $i];
    for ($i = 0; $i < $r; $i++) $result .= $out[2 * $i + 1];
    return $result;
}

function scrypt_salsa8(string $block): string
{
    $x = [];
    for ($i = 0; $i < 16; $i++) $x[$i] = unpack('V', substr($block, $i * 4, 4))[1];
    $original = $x;
    for ($round = 0; $round < 8; $round += 2) {
        $x[4] ^= scrypt_rotl($x[0] + $x[12], 7); $x[8] ^= scrypt_rotl($x[4] + $x[0], 9); $x[12] ^= scrypt_rotl($x[8] + $x[4], 13); $x[0] ^= scrypt_rotl($x[12] + $x[8], 18);
        $x[9] ^= scrypt_rotl($x[5] + $x[1], 7); $x[13] ^= scrypt_rotl($x[9] + $x[5], 9); $x[1] ^= scrypt_rotl($x[13] + $x[9], 13); $x[5] ^= scrypt_rotl($x[1] + $x[13], 18);
        $x[14] ^= scrypt_rotl($x[10] + $x[6], 7); $x[2] ^= scrypt_rotl($x[14] + $x[10], 9); $x[6] ^= scrypt_rotl($x[2] + $x[14], 13); $x[10] ^= scrypt_rotl($x[6] + $x[2], 18);
        $x[3] ^= scrypt_rotl($x[15] + $x[11], 7); $x[7] ^= scrypt_rotl($x[3] + $x[15], 9); $x[11] ^= scrypt_rotl($x[7] + $x[3], 13); $x[15] ^= scrypt_rotl($x[11] + $x[7], 18);
        $x[1] ^= scrypt_rotl($x[0] + $x[3], 7); $x[2] ^= scrypt_rotl($x[1] + $x[0], 9); $x[3] ^= scrypt_rotl($x[2] + $x[1], 13); $x[0] ^= scrypt_rotl($x[3] + $x[2], 18);
        $x[6] ^= scrypt_rotl($x[5] + $x[4], 7); $x[7] ^= scrypt_rotl($x[6] + $x[5], 9); $x[4] ^= scrypt_rotl($x[7] + $x[6], 13); $x[5] ^= scrypt_rotl($x[4] + $x[7], 18);
        $x[11] ^= scrypt_rotl($x[10] + $x[9], 7); $x[8] ^= scrypt_rotl($x[11] + $x[10], 9); $x[9] ^= scrypt_rotl($x[8] + $x[11], 13); $x[10] ^= scrypt_rotl($x[9] + $x[8], 18);
        $x[12] ^= scrypt_rotl($x[15] + $x[14], 7); $x[13] ^= scrypt_rotl($x[12] + $x[15], 9); $x[14] ^= scrypt_rotl($x[13] + $x[12], 13); $x[15] ^= scrypt_rotl($x[14] + $x[13], 18);
    }
    $result = '';
    for ($i = 0; $i < 16; $i++) $result .= pack('V', ($x[$i] + $original[$i]) & 0xffffffff);
    return $result;
}

function scrypt_rotl(int $value, int $bits): int
{
    $value &= 0xffffffff;
    return (($value << $bits) | ($value >> (32 - $bits))) & 0xffffffff;
}
function scrypt_little_endian(string $bytes): int { return unpack('V', $bytes)[1]; }

function password_hash_legacy(string $password): string
{
    $salt = bin2hex(random_bytes(16));
    return 'scrypt$' . $salt . '$' . bin2hex(scrypt_binary($password, $salt));
}

function verify_password(string $password, string $stored): bool
{
    $parts = explode('$', $stored);
    if (count($parts) !== 3 || $parts[0] !== 'scrypt' || !ctype_xdigit($parts[2])) return false;
    $actual = scrypt_binary($password, $parts[1]);
    $expected = hex2bin($parts[2]);
    return $expected !== false && hash_equals($expected, $actual);
}

function current_user(): ?array
{
    $token = $_COOKIE[SESSION_COOKIE] ?? '';
    if ($token === '') return null;
    $stmt = db()->prepare("SELECT u.id, u.username, u.full_name, u.role, u.active, COALESCE(jsonb_object_agg(p.page_key, jsonb_build_object('view', p.can_view, 'create', p.can_create, 'edit', p.can_edit, 'delete', p.can_delete)) FILTER (WHERE p.page_key IS NOT NULL), '{}'::jsonb) AS permissions FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN page_permissions p ON p.user_id=u.id WHERE s.token_hash=:token AND s.expires_at > NOW() AND u.active=TRUE GROUP BY u.id");
    $stmt->execute(['token' => hash_session_token($token)]);
    $user = $stmt->fetch();
    if (!$user) return null;
    $user['permissions'] = json_decode((string) $user['permissions'], true) ?: [];
    return $user;
}

function can(array $user, string $page, string $capability = 'view'): bool
{
    return $user['role'] === 'قائد الفرقة' || !empty($user['permissions'][$page][$capability]);
}

function require_auth(bool $json = true): array
{
    $user = current_user();
    if ($user) return $user;
    if ($json) json_response(['error' => 'يجب تسجيل الدخول أولاً'], 401);
    header('Location: /login', true, 302); exit;
}

function require_permission(string $page, string $capability = 'view', bool $json = true): array
{
    $user = require_auth($json);
    if (!can($user, $page, $capability)) {
        if ($json) json_response(['error' => 'لا تملك الصلاحية لتنفيذ هذا الإجراء'], 403);
        http_response_code(403); echo '<!doctype html><meta charset="utf-8"><title>غير مخول</title><link rel="stylesheet" href="/app.css"><main class="login-card"><h1>أنت غير مخول</h1><p>لا تملك صلاحية الوصول إلى هذه الصفحة.</p><a class="button primary" href="/dashboard">العودة للرئيسية</a></main>'; exit;
    }
    return $user;
}

function create_session(int $userId): string
{
    $token = bin2hex(random_bytes(32));
    $stmt = db()->prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (:id, :token, NOW() + INTERVAL '7 days')");
    $stmt->execute(['id' => $userId, 'token' => hash_session_token($token)]);
    return $token;
}

function set_session_cookie(string $token): void
{
    setcookie(SESSION_COOKIE, $token, ['expires' => time() + 604800, 'path' => '/', 'secure' => env_value('NODE_ENV') === 'production', 'httponly' => true, 'samesite' => 'Lax']);
}
function logout_session(): void
{
    if (!empty($_COOKIE[SESSION_COOKIE])) db()->prepare('DELETE FROM sessions WHERE token_hash=:token')->execute(['token' => hash_session_token($_COOKIE[SESSION_COOKIE])]);
    setcookie(SESSION_COOKIE, '', ['expires' => time() - 3600, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
}
