<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once '../config.php';
require_once '../db.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);

    echo json_encode([
        'success' => false,
        'message' => 'Please log in first.'
    ]);

    exit;
}

$userId = (int) $_SESSION['user_id'];

try {

    $action = $_POST['action'] ?? '';

    if ($action === 'delete') {

        $scanId = isset($_POST['id']) ? (int) $_POST['id'] : 0;

        if ($scanId <= 0) {
            http_response_code(400);

            echo json_encode([
                'success' => false,
                'message' => 'Invalid scan ID.'
            ]);

            exit;
        }

        $stmt = $pdo->prepare("
            DELETE FROM scans
            WHERE id = :id
            AND user_id = :user_id
        ");

        $stmt->execute([
            ':id' => $scanId,
            ':user_id' => $userId
        ]);

        if ($stmt->rowCount() === 0) {
            echo json_encode([
                'success' => false,
                'message' => 'Scan record not found.'
            ]);

            exit;
        }

        echo json_encode([
            'success' => true,
            'message' => 'Scan deleted successfully.'
        ]);

        exit;
    }

    if ($action === 'delete_all') {

        $stmt = $pdo->prepare("
            DELETE FROM scans
            WHERE user_id = :user_id
        ");

        $stmt->execute([
            ':user_id' => $userId
        ]);

        echo json_encode([
            'success' => true,
            'message' => 'All scan history has been deleted.',
            'deleted' => $stmt->rowCount()
        ]);

        exit;
    }

    http_response_code(400);

    echo json_encode([
        'success' => false,
        'message' => 'Invalid action.'
    ]);

} catch (PDOException $e) {

    http_response_code(500);

    echo json_encode([
        'success' => false,
        'message' => 'Unable to delete scan history.'
    ]);
}