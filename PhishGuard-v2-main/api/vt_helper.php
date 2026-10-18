<?php

function check_dangerous_sites(PDO $pdo, string $url): array
{
    $forParsing = preg_match('#^https?://#i', $url)
        ? $url
        : 'https://' . $url;

    $parts = parse_url($forParsing);

    if ($parts === false || empty($parts['host'])) {
        return ['matched' => false];
    }

    $host = strtolower($parts['host']);
    $host = preg_replace('/^www\./', '', $host);

    try {
        $stmt = $pdo->prepare("
            SELECT url, host, category, risk_level, notes
            FROM dangerous_sites
            WHERE host = :host
               OR :host LIKE CONCAT('%.', host)
               OR host LIKE CONCAT('%.', :host2)
            LIMIT 1
        ");
        $stmt->execute([':host' => $host, ':host2' => $host]);
        $row = $stmt->fetch();

        if (!$row) {
            return ['matched' => false];
        }

        return [
            'matched'    => true,
            'url'        => $row['url'],
            'host'       => $row['host'],
            'category'   => $row['category'],
            'risk_level' => $row['risk_level'],
            'notes'      => $row['notes']
        ];

    } catch (PDOException $e) {
        return ['matched' => false];
    }
}