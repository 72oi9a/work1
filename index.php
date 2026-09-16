<?php
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = $path === '/' ? '/' : rtrim($path, '/');
if (str_starts_with($path, '/api/')) {
    require __DIR__ . '/php/api.php';
    exit;
}

$routes = [
    '/' => 'login.php', '/login' => 'login.php', '/dashboard' => 'dashboard.php',
    '/forms' => 'forms.php', '/forms-generator' => 'forms-generator.php',
    '/reports' => 'reports.php', '/members' => 'members.php',
    '/supervisors' => 'supervisors.php', '/settings' => 'settings.php',
];
$target = $routes[$path] ?? null;
if ($target && is_file(__DIR__ . '/' . $target)) {
    require __DIR__ . '/' . $target;
    exit;
}
http_response_code(404);
header('Content-Type: text/plain; charset=utf-8');
echo 'Not found';
