<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once '../config.php';
require_once '../db.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);

    echo json_encode([
        'success' => false,
        'message' => 'Unauthorized access.'
    ]);

    exit;
}

try {

    $stmt = $pdo->prepare("
        SELECT
            id,
            title,
            message,
            created_at
        FROM safety_alerts
        WHERE is_active = 1
        ORDER BY created_at DESC
        LIMIT 1
    ");

    $stmt->execute();

    $alert = $stmt->fetch();

    if (!$alert) {
        echo json_encode([
            'success' => true,
            'has_alert' => false,
            'alert' => null
        ], JSON_UNESCAPED_UNICODE);

        exit;
    }

    echo json_encode([
        'success' => true,
        'has_alert' => true,
        'alert' => [
            'id' => (int) $alert['id'],
            'title' => $alert['title'],
            'message' => $alert['message'],
            'created_at' => $alert['created_at']
        ]
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {

    http_response_code(500);

    echo json_encode([
        'success' => false,
        'message' => 'Unable to load safety alert.'
    ]);
}