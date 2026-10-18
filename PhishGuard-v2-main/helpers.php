<?php

/**
 * Detect where the request came from.
 *
 * Returns an array: ['source' => 'web'|'mobile', 'app_client' => 'desktop_browser'|'mobile_browser'|'android_app']
 */
function detectSource(): array
{
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    /* 1. PhishGuard Android app (custom WebView UA token) */
    if (stripos($ua, 'PhishGuardApp') !== false) {
        return [
            'source'     => 'mobile',
            'app_client' => 'android_app',
        ];
    }

    /* 2. Mobile browser (Chrome/Safari/Firefox on Android or iOS) */
    if (preg_match('/Mobile|Android|iPhone|iPad|iPod|Windows Phone/i', $ua)) {
        return [
            'source'     => 'mobile',
            'app_client' => 'mobile_browser',
        ];
    }

    /* 3. Desktop browser */
    return [
        'source'     => 'web',
        'app_client' => 'desktop_browser',
    ];
}