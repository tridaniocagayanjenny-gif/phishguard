<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require_once '../config.php';
require_once '../db.php';

$pageTitle    = 'Dangerous Sites';
$pageSubtitle = 'Known threats and reported malicious links';
$userName     = $_SESSION['full_name'] ?? 'User';
$userInitial  = strtoupper(substr($userName, 0, 1));

$search = trim($_GET['q'] ?? '');

try {
    /* Dynamic list from threat_reports (SUSPICIOUS & DANGEROUS scans) */
    $sql = "
        SELECT 
            threat_value AS url,
            result,
            risk_score,
            created_at
        FROM threat_reports
        WHERE result IN ('SUSPICIOUS', 'DANGEROUS')
    ";
    
    $params = [];

    if ($search !== '') {
        $sql .= " AND threat_value LIKE ? ";
        $params[] = '%' . $search . '%';
    }

    $sql .= " ORDER BY created_at DESC LIMIT 100";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $scannedThreats = $stmt->fetchAll();

    /* Static list from dangerous_sites */
    $staticSql = "SELECT url_pattern, category, notes FROM dangerous_sites WHERE is_active = 1";
    $staticParams = [];

    if ($search !== '') {
        $staticSql .= " AND url_pattern LIKE ? ";
        $staticParams[] = '%' . $search . '%';
    }

    $staticSql .= " ORDER BY url_pattern ASC LIMIT 100";

    $stmt2 = $pdo->prepare($staticSql);
    $stmt2->execute($staticParams);
    $staticThreats = $stmt2->fetchAll();

} catch (PDOException $e) {
    $scannedThreats = [];
    $staticThreats  = [];
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dangerous Sites | PhishGuard</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
    
    <!-- Inline CSS para sure na may design -->
    <style>
        <?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
    </style>
</head>

<body>

<div class="pg-layout">

    <?php require_once 'includes/sidebar.php'; ?>

    <main class="pg-main">

        <?php require_once 'includes/topbar.php'; ?>

        <div class="pg-content">

            <div class="pg-hero">
                <span class="pg-eyebrow">
                    <i class="fa-solid fa-skull-crossbones"></i>
                    Threat Database
                </span>
                <h1>Dangerous Sites List</h1>
                <p>
                    Browse known phishing URLs, reported malicious sites, and live threats flagged by the PhishGuard scanner.
                </p>
            </div>

            <!-- Search Bar -->
            <div class="pg-card" style="margin-bottom: 20px;">
                <div class="pg-card-body">
                    <form method="GET" style="display:flex; gap: 10px;">
                        <input 
                            type="text" 
                            name="q" 
                            class="pg-input" 
                            placeholder="Search domain or URL pattern..." 
                            value="<?= htmlspecialchars($search) ?>"
                            style="flex:1;"
                        >
                        <button type="submit" class="pg-btn" style="padding: 0 25px;">
                            <i class="fa-solid fa-search"></i> Search
                        </button>
                        <?php if($search !== ''): ?>
                            <a href="dangerous.php" class="pg-btn pg-btn-secondary" style="padding: 0 20px; text-decoration:none;">Clear</a>
                        <?php endif; ?>
                    </form>
                </div>
            </div>

            <div class="pg-grid-2">

                <!-- Live Threats (From Scans) -->
                <div class="pg-card">
                    <div class="pg-card-header">
                        <div>
                            <h3><i class="fa-solid fa-biohazard" style="color:#f59e0b; margin-right:8px;"></i> Live Threats</h3>
                            <p style="color:#64748b; font-size:11px; margin:4px 0 0;">Flagged by users and VirusTotal</p>
                        </div>
                    </div>
                    <div class="pg-card-body" style="padding: 0;">
                        
                        <?php if (!$scannedThreats): ?>
                            <div style="padding: 40px 20px; text-align: center; color: #64748b;">
                                <i class="fa-solid fa-shield-check" style="font-size: 30px; margin-bottom: 10px; opacity: 0.5;"></i>
                                <p>No live threats found.</p>
                            </div>
                        <?php else: ?>
                            <div class="pg-table-wrap">
                                <table class="pg-table">
                                    <thead>
                                        <tr>
                                            <th>URL</th>
                                            <th>Result</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($scannedThreats as $t): ?>
                                            <tr>
                                                <td>
                                                    <div style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size:11px; font-family: monospace;" title="<?= htmlspecialchars($t['url']) ?>">
                                                        <?= htmlspecialchars($t['url']) ?>
                                                    </div>
                                                </td>
                                                <td>
                                                    <span class="pg-badge pg-badge-<?= strtolower($t['result']) ?>">
                                                        <?= htmlspecialchars($t['result']) ?>
                                                    </span>
                                                </td>
                                                <td>
                                                    <a href="mini_browser.php?url=<?= urlencode($t['url']) ?>&result=<?= $t['result'] ?>&from=dangerous.php" class="pg-btn" style="padding: 4px 8px; font-size: 10px; min-height: unset; box-shadow:none;">
                                                        Preview
                                                    </a>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>

                    </div>
                </div>

                <!-- Static Blacklist (From DB) -->
                <div class="pg-card">
                    <div class="pg-card-header">
                        <div>
                            <h3><i class="fa-solid fa-list-ul" style="color:#38bdf8; margin-right:8px;"></i> Blacklist Database</h3>
                            <p style="color:#64748b; font-size:11px; margin:4px 0 0;">Pre-configured malicious patterns</p>
                        </div>
                    </div>
                    <div class="pg-card-body" style="padding: 0;">
                        
                        <?php if (!$staticThreats): ?>
                            <div style="padding: 40px 20px; text-align: center; color: #64748b;">
                                <p>No entries found.</p>
                            </div>
                        <?php else: ?>
                            <div class="pg-table-wrap">
                                <table class="pg-table">
                                    <thead>
                                        <tr>
                                            <th>Domain Pattern</th>
                                            <th>Category</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($staticThreats as $st): ?>
                                            <tr>
                                                <td style="font-family: monospace; font-size:11px; color:#fca5a5;">
                                                    <?= htmlspecialchars($st['url_pattern']) ?>
                                                </td>
                                                <td>
                                                    <span class="pg-badge pg-badge-dangerous">
                                                        <?= htmlspecialchars($st['category']) ?>
                                                    </span>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>

                    </div>
                </div>

            </div>

        </div>

    </main>

</div>

</body>
</html>