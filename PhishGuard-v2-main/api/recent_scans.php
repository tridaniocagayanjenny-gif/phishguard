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

$userId = (int) $_SESSION['user_id'];

try {

    $hours = isset($_GET['hours']) ? (int) $_GET['hours'] : 48;

    if ($hours < 1) {
        $hours = 48;
    }

    if ($hours > 168) {
        $hours = 168;
    }

    $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 50;

    if ($limit < 1) {
        $limit = 50;
    }

    if ($limit > 100) {
        $limit = 100;
    }

    $type = isset($_GET['type']) ? trim($_GET['type']) : '';

    $allowedTypes = [
        'url',
        'image',
        'qr',
        'sms'
    ];

    $conditions = [
        'user_id = :user_id',
        'created_at >= DATE_SUB(NOW(), INTERVAL :hours HOUR)'
    ];

    $params = [
        ':user_id' => $userId,
        ':hours' => $hours
    ];

    if ($type !== '' && in_array($type, $allowedTypes, true)) {

        $conditions[] = 'scan_type = :scan_type';

        $params[':scan_type'] = $type;
    }

    $where = implode(' AND ', $conditions);

    $sql = "
        SELECT
            id,
            scan_type,
            input_value,
            result,
            risk_score,
            explanation,
            source,
            created_at
        FROM scans
        WHERE {$where}
        ORDER BY created_at DESC
        LIMIT {$limit}
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $rows = $stmt->fetchAll();

    $scans = [];

    foreach ($rows as $row) {

        $scans[] = [
            'id' => (int) $row['id'],
            'scan_type' => $row['scan_type'],
            'input_value' => $row['input_value'],
            'result' => $row['result'],
            'risk_score' => (int) $row['risk_score'],
            'explanation' => $row['explanation'],
            'source' => $row['source'],
            'created_at' => $row['created_at']
        ];
    }

    $countSql = "
        SELECT COUNT(*)
        FROM scans
        WHERE {$where}
    ";

    $countStmt = $pdo->prepare($countSql);
    $countStmt->execute($params);

    $total = (int) $countStmt->fetchColumn();

    echo json_encode([
        'success' => true,
        'hours' => $hours,
        'total' => $total,
        'count' => count($scans),
        'scans' => $scans
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {

    http_response_code(500);

    echo json_encode([
        'success' => false,
        'message' => 'Unable to load recent scans.'
    ]);
}