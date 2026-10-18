<?php
$currentPage = basename($_SERVER['PHP_SELF']);
?>

<aside class="pg-sidebar">

    <div class="pg-sidebar-top">

        <div class="pg-brand">

            <div class="pg-brand-icon">
                <i class="fa-solid fa-shield-halved"></i>
            </div>

            <div>
                <div class="pg-brand-name">PHISHGUARD</div>
                <span class="pg-brand-sub">Cybersecurity Platform</span>
            </div>

        </div>

        <nav class="pg-nav">

            <a href="home.php" class="<?= $currentPage === 'home.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-house"></i>
                <span>Dashboard</span>
            </a>

            <a href="scanner.php" class="<?= $currentPage === 'scanner.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-magnifying-glass"></i>
                <span>Scan Center</span>
            </a>

            <a href="recent.php" class="<?= $currentPage === 'recent.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-clock-rotate-left"></i>
                <span>Recent Scans</span>
            </a>

            <a href="history.php" class="<?= $currentPage === 'history.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-chart-column"></i>
                <span>Scan History</span>
            </a>
            <a href="mini_browser.php" class="<?= basename($_SERVER['PHP_SELF']) === 'mini_browser.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-compass"></i>
                <span>Mini Browser</span>
            </a>

            <a href="dangerous.php" class="...">
    <i class="fa-solid fa-skull-crossbones"></i>
    Dangerous Sites
</a>

<div class="pg-nav-group">

    <div class="pg-nav-parent">

        <a href="guidelines.php">
            <i class="fa-solid fa-shield-heart"></i>
            <span>Safety Guidelines</span>
        </a>

        <button
            type="button"
            class="pg-submenu-toggle"
            aria-label="Toggle Safety Guidelines submenu"
            aria-expanded="<?= in_array($currentPage, ['guidelines.php', 'guidelines_tl.php']) ? 'true' : 'false' ?>"
        >
            <i class="fa-solid fa-chevron-down"></i>
        </button>

    </div>

    <div class="pg-submenu <?= in_array($currentPage, ['guidelines.php', 'guidelines_tl.php']) ? 'open' : '' ?>">

        <a href="guidelines.php" class="<?= $currentPage === 'guidelines.php' ? 'active' : '' ?>">
            <i class="fa-solid fa-language"></i>
            <span>English</span>
        </a>

        <a href="guidelines_tl.php" class="<?= $currentPage === 'guidelines_tl.php' ? 'active' : '' ?>">
            <i class="fa-solid fa-flag"></i>
            <span>Tagalog</span>
        </a>

    </div>

</div>

        </nav>

    </div>

    <div class="pg-sidebar-bottom">

        <div class="pg-security-card">

            <div class="pg-security-title">
                <span class="pg-status-dot"></span>
                Protection Active
            </div>

            <div class="pg-security-text">
                PhishGuard is monitoring
            </div>

        </div>

        <nav class="pg-nav">

            <a href="logout.php">
                <i class="fa-solid fa-right-from-bracket"></i>
                <span>Logout</span>
            </a>

        </nav>

    </div>

</aside>