<?php
// PHP-compatible entry point. Node/Express remains the real API and database service.
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (str_starts_with($path, '/api/')) {
    $target = 'http://127.0.0.1:' . (getenv('PORT') ?: '5000') . $path;
    if (!empty($_SERVER['QUERY_STRING'])) {
        $target .= '?' . $_SERVER['QUERY_STRING'];
    }

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $headers = [];
    foreach (getallheaders() ?: [] as $name => $value) {
        if (strtolower($name) === 'host') {
            continue;
        }
        $headers[] = $name . ': ' . $value;
    }

    $curl = curl_init($target);
    curl_setopt_array($curl, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_POSTFIELDS => file_get_contents('php://input'),
        CURLOPT_TIMEOUT => 30,
    ]);
    $result = curl_exec($curl);
    if ($result === false) {
        http_response_code(503);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'خدمة الخادم غير متاحة'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    http_response_code($status ?: 502);

    $responseHeaders = substr($result, 0, $headerSize);
    foreach (preg_split("/\r\n|\n|\r/", trim($responseHeaders)) as $header) {
        if (stripos($header, 'HTTP/') === 0 || stripos($header, 'Transfer-Encoding:') === 0) {
            continue;
        }
        if ($header !== '') {
            header($header, false);
        }
    }
    echo substr($result, $headerSize);
    exit;
}

header('Content-Type: text/html; charset=utf-8');
readfile(__DIR__ . '/index.html');
