<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once '../config.php';
require_once '../db.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'You must be logged in.']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Invalid request method.']);
    exit;
}

$userId = (int) $_SESSION['user_id'];

$url             = trim($_POST['url'] ?? '');
$detectedResult  = strtoupper(trim($_POST['detected_result'] ?? ''));
$detectedScore   = (int) ($_POST['detected_score'] ?? 0);
$userVerdict     = strtoupper(trim($_POST['user_verdict'] ?? ''));
$userNote        = trim($_POST['user_note'] ?? '');
$scanId          = isset($_POST['scan_id']) ? (int) $_POST['scan_id'] : null;

if ($url === '' || strlen($url) > 2000) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid URL.']);
    exit;
}

if (!in_array($detectedResult, ['SAFE', 'SUSPICIOUS', 'DANGEROUS'], true)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid detected result.']);
    exit;
}

if (!in_array($userVerdict, ['SAFE', 'SUSPICIOUS', 'DANGEROUS'], true)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid user verdict.']);
    exit;
}

if (strlen($userNote) > 1000) {
    $userNote = substr($userNote, 0, 1000);
}

try {
    $stmt = $pdo->prepare("
        INSERT INTO scan_feedback
        (scan_id, user_id, url, detected_result, detected_score, user_verdict, user_note, status)
        VALUES (:scan_id, :user_id, :url, :detected_result, :detected_score, :user_verdict, :user_note, 'pending')
    ");

    $stmt->execute([
        ':scan_id'         => $scanId,
        ':user_id'         => $userId,
        ':url'             => $url,
        ':detected_result' => $detectedResult,
        ':detected_score'  => $detectedScore,
        ':user_verdict'    => $userVerdict,
        ':user_note'       => $userNote,
    ]);

    $feedbackId = (int) $pdo->lastInsertId();

    echo json_encode([
        'success'     => true,
        'feedback_id' => $feedbackId,
        'message'     => 'Thank you! Your feedback helps improve PhishGuard detection.',
    ]);

} catch (PDOException $e) {
    error_log('PhishGuard feedback error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error'   => 'Could not save feedback.',
    ]);
}