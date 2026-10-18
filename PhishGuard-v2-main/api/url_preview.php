<?php

session_start();

header('Content-Type: application/json; charset=utf-8');

require_once '../db.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false]);
    exit;
}

$query = trim($_GET['q'] ?? '');

if (strlen($query) < 3) {
    echo json_encode(['success' => false]);
    exit;
}

$queryLower = strtolower($query);
$queryLower = preg_replace('#^https?://#', '', $queryLower);
$queryLower = preg_replace('#/.*$#', '', $queryLower);

$items = [];

try {

    $stmt = $pdo->prepare("
        SELECT url, host, category, risk_level, notes
        FROM dangerous_sites
        WHERE host LIKE :q
           OR url LIKE :q2
        ORDER BY
            CASE WHEN host = :exact THEN 0 ELSE 1 END,
            host ASC
        LIMIT 6
    ");

    $stmt->execute([
        ':q'     => '%' . $queryLower . '%',
        ':q2'    => '%' . $query . '%',
        ':exact' => $queryLower
    ]);

    while ($row = $stmt->fetch()) {

        $badgeColor = $row['risk_level'] === 'DANGEROUS' ? '#ef4444' : '#f59e0b';

        $items[] = [
            'url'        => $row['url'],
            'host'       => $row['host'],
            'label'      => $row['host'],
            'sublabel'   => $row['category'] . ' — ' . $row['notes'],
            'badgeColor' => $badgeColor,
            'badgeText'  => $row['risk_level']
        ];
    }

} catch (PDOException $e) {
    /* silent */
}

if (filter_var($query, FILTER_VALIDATE_URL) || preg_match('#^[a-z0-9\-]+\.[a-z]{2,}#i', $query)) {

    $normalized = preg_match('#^https?://#i', $query) ? $query : 'https://' . $query;

    $items[] = [
        'url'        => $normalized,
        'host'       => parse_url($normalized, PHP_URL_HOST) ?: '',
        'label'      => 'Open: ' . $query,
        'sublabel'   => 'Visit this URL in the mini browser preview',
        'badgeColor' => '#38bdf8',
        'badgeText'  => 'OPEN'
    ];
}

if (empty($items)) {
    echo json_encode(['success' => false]);
    exit;
}

$html = '';

foreach ($items as $item) {

    $url    = htmlspecialchars($item['url'], ENT_QUOTES);
    $label  = htmlspecialchars($item['label']);
    $sub    = htmlspecialchars($item['sublabel']);
    $color  = $item['badgeColor'];
    $badge  = htmlspecialchars($item['badgeText']);

    $html .= '<div class="pg-mb-item" data-url="' . $url . '">'
           . '<div class="pg-mb-item-icon"><i class="fa-solid fa-globe"></i></div>'
           . '<div class="pg-mb-item-text">'
           . '<strong>' . $label . '</strong>'
           . '<span>' . $sub . '</span>'
           . '</div>'
           . '<span class="pg-mb-badge" style="background:' . $color . '22;color:' . $color . ';border:1px solid ' . $color . '44;">'
           . $badge
           . '</span>'
           . '</div>';
}

echo json_encode([
    'success' => true,
    'html'    => $html
]);