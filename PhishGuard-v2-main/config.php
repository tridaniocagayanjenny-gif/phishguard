<?php

define('DB_HOST', 'localhost');
define('DB_NAME', 'phishguard');
define('DB_USER', 'root');
define('DB_PASS', '');

define('APP_NAME', 'PhishGuard');

if (!defined('BASE_URL')) {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $scheme = explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO'])[0];
    }

    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $basePath = '/phishguard';

    define('BASE_URL', $scheme . '://' . $host . $basePath);
    define('API_URL',  BASE_URL . '/api/');
}
?>