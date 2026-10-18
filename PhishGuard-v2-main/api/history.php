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

    $type = isset($_GET['type']) ? trim($_GET['type']) : '';
    $search = isset($_GET['search']) ? trim($_GET['search']) : '';
    $limit = isset($_GET['limit']) ? (int) $_GET['limit'] : 50;

    if ($limit < 1) {
        $limit = 50;
    }

    if ($limit > 100) {
        $limit = 100;
    }

    $conditions = ['user_id = :user_id'];

    $params = [
        ':user_id' => $userId
    ];

    $allowedTypes = [
        'url',
        'image',
        'qr',
        'sms'
    ];

    if ($type !== '' && in_array($type, $allowedTypes, true)) {

        $conditions[] = 'scan_type = :scan_type';

        $params[':scan_type'] = $type;
    }

    if ($search !== '') {

        $conditions[] = '(
            input_value LIKE :search
            OR result LIKE :search
            OR explanation LIKE :search
        )';

        $params[':search'] = '%' . $search . '%';
    }

    $where = implode(' AND ', $conditions);

    $countSql = "
        SELECT COUNT(*) AS total
        FROM scans
        WHERE {$where}
    ";

    $countStmt = $pdo->prepare($countSql);
    $countStmt->execute($params);

    $total = (int) $countStmt->fetchColumn();

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

    $history = [];

    foreach ($rows as $row) {

        $history[] = [
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

    echo json_encode([
        'success' => true,
        'total' => $total,
        'count' => count($history),
        'history' => $history
    ], JSON_UNESCAPED_UNICODE);

} catch (PDOException $e) {

    http_response_code(500);

    echo json_encode([
        'success' => false,
        'message' => 'Unable to load scan history.'
    ]);
}