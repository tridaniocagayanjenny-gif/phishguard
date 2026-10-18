<?php

session_start();

require_once '../config.php';
require_once '../db.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$url = trim($_GET['url'] ?? '');

if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
    header('Location: scanner.php?type=url');
    exit;
}

$host = parse_url($url, PHP_URL_HOST) ?: '';

$pageTitle    = 'Link Preview';
$pageSubtitle = 'Safe preview of the URL content';
$userName     = $_SESSION['full_name'] ?? 'User';
$userInitial  = strtoupper(substr($userName, 0, 1));

$previewTitle = '';
$previewDesc  = '';
$previewText  = '';
$previewLinks = [];
$fetchError   = '';

$context = stream_context_create([
    'http' => [
        'method'        => 'GET',
        'timeout'       => 6,
        'ignore_errors' => true,
        'header'        => "User-Agent: Mozilla/5.0 (compatible; PhishGuardPreview/1.0)\r\n"
    ],
    'ssl' => [
        'verify_peer'      => false,
        'verify_peer_name' => false
    ]
]);

$html = @file_get_contents($url, false, $context);

if ($html === false || $html === '') {

    $fetchError = 'Unable to fetch the URL content. The site may be offline, blocking our request, or the URL may be unsafe to load.';

} else {

    if (preg_match('#<title[^>]*>(.*?)</title>#is', $html, $m)) {
        $previewTitle = trim(html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'));
    }

    if (preg_match('#<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)#i', $html, $m)) {
        $previewDesc = trim(html_entity_decode($m[1], ENT_QUOTES, 'UTF-8'));
    }

    $stripped = preg_replace('#<script[^>]*>.*?</script>#is', '', $html);
    $stripped = preg_replace('#<style[^>]*>.*?</style>#is', '', $stripped);
    $text     = strip_tags($stripped);
    $text     = html_entity_decode($text, ENT_QUOTES, 'UTF-8');
    $text     = preg_replace('/\s+/', ' ', $text);
    $previewText = trim(substr($text, 0, 800));

    if (preg_match_all('#<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>#is', $html, $links, PREG_SET_ORDER)) {
        foreach (array_slice($links, 0, 8) as $link) {
            $previewLinks[] = [
                'href' => $link[1],
                'text' => trim(strip_tags($link[2]))
            ];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Link Preview | PhishGuard</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>

<div class="pg-layout">

    <?php require_once 'includes/sidebar.php'; ?>

    <main class="pg-main">

        <?php require_once 'includes/topbar.php'; ?>

        <div class="pg-content">

            <div class="pg-section-head" style="margin-bottom:14px;">
                <div>
                    <h2>Link Preview</h2>
                    <p style="word-break:break-all;color:#94a3b8;font-size:12px;margin-top:4px;">
                        <?= htmlspecialchars($url) ?>
                    </p>
                </div>
                <a href="scanner.php?type=url" class="pg-btn" style="text-decoration:none;">
                    <i class="fa-solid fa-arrow-left"></i>
                    Back to Scanner
                </a>
            </div>

            <?php if ($fetchError !== ''): ?>

                <div class="pg-card">
                    <div class="pg-card-body">
                        <div class="pg-alert" style="border-color:rgba(239,68,68,.28);background:rgba(239,68,68,.06);">
                            <div class="pg-alert-icon" style="background:rgba(239,68,68,.12);color:#ef4444;">
                                <i class="fa-solid fa-triangle-exclamation"></i>
                            </div>
                            <div>
                                <h4>Unable to load the URL</h4>
                                <p><?= htmlspecialchars($fetchError) ?></p>
                            </div>
                        </div>
                    </div>
                </div>

            <?php else: ?>

                <div class="pg-card" style="margin-bottom:20px;">
                    <div class="pg-card-header">
                        <h3><i class="fa-solid fa-heading" style="color:#38bdf8;margin-right:7px;"></i> Page Title</h3>
                    </div>
                    <div class="pg-card-body">
                        <div style="padding:12px 14px;background:rgba(2,6,23,.5);border:1px solid rgba(148,163,184,.15);border-radius:12px;color:#f8fafc;font-size:14px;font-weight:600;">
                            <?= htmlspecialchars($previewTitle ?: '(no title found)') ?>
                        </div>
                    </div>
                </div>

                <?php if ($previewDesc !== ''): ?>
                <div class="pg-card" style="margin-bottom:20px;">
                    <div class="pg-card-header">
                        <h3><i class="fa-solid fa-align-left" style="color:#38bdf8;margin-right:7px;"></i> Meta Description</h3>
                    </div>
                    <div class="pg-card-body">
                        <div style="padding:12px 14px;background:rgba(2,6,23,.5);border:1px solid rgba(148,163,184,.15);border-radius:12px;color:#cbd5e1;font-size:12.5px;line-height:1.6;">
                            <?= htmlspecialchars($previewDesc) ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

                <div class="pg-card" style="margin-bottom:20px;">
                    <div class="pg-card-header">
                        <h3><i class="fa-solid fa-file-lines" style="color:#38bdf8;margin-right:7px;"></i> Page Text (First 800 characters)</h3>
                    </div>
                    <div class="pg-card-body">
                        <div style="padding:14px;background:rgba(2,6,23,.5);border:1px solid rgba(148,163,184,.15);border-radius:12px;color:#cbd5e1;font-size:12.5px;line-height:1.7;max-height:340px;overflow-y:auto;">
                            <?= htmlspecialchars($previewText ?: '(no readable text found)') ?>
                        </div>
                    </div>
                </div>

                <?php if ($previewLinks): ?>
                <div class="pg-card" style="margin-bottom:20px;">
                    <div class="pg-card-header">
                        <h3><i class="fa-solid fa-link" style="color:#38bdf8;margin-right:7px;"></i> Links Found on the Page</h3>
                    </div>
                    <div class="pg-card-body">
                        <div style="display:grid;gap:8px;">
                            <?php foreach ($previewLinks as $link): ?>
                                <div style="padding:10px 12px;background:rgba(2,6,23,.5);border:1px solid rgba(148,163,184,.12);border-radius:10px;font-size:12px;">
                                    <div style="color:#f8fafc;font-weight:600;margin-bottom:3px;">
                                        <?= htmlspecialchars($link['text'] ?: '(link)') ?>
                                    </div>
                                    <div style="color:#94a3b8;font-size:11px;word-break:break-all;">
                                        <?= htmlspecialchars($link['href']) ?>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

            <?php endif; ?>

        </div>

    </main>

</div>

</body>
</html>