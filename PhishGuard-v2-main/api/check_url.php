<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once '../db.php';
require_once '../helpers.php';
require_once 'vt_helper.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['blocked' => false]);
    exit;
}

$url = trim($_GET['url'] ?? '');

if ($url === '') {
    echo json_encode(['blocked' => false]);
    exit;
}

$blacklist = check_dangerous_sites($pdo, $url);

if ($blacklist['matched'] && $blacklist['risk_level'] === 'DANGEROUS') {
    echo json_encode([
        'blocked'  => true,
        'category' => $blacklist['category'],
        'notes'    => $blacklist['notes']
    ]);
    exit;
}

echo json_encode(['blocked' => false]);