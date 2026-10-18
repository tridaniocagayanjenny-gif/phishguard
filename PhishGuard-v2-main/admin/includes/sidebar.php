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
                <span class="pg-brand-sub">Admin Security Center</span>
            </div>

        </div>

        <div class="pg-section-label">ADMIN CONSOLE</div>

        <nav class="pg-nav">

            <a href="dashboard.php" class="<?= $currentPage === 'dashboard.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-chart-pie"></i>
                <span>Dashboard</span>
            </a>

            <a href="scans.php" class="<?= $currentPage === 'scans.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-magnifying-glass-chart"></i>
                <span>Scan Monitor</span>
            </a>

            <a href="users.php" class="<?= $currentPage === 'users.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-users"></i>
                <span>User Accounts</span>
            </a>

            <a href="threats.php" class="<?= $currentPage === 'threats.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>Threat Monitor</span>
            </a>

            <a href="alerts.php" class="<?= $currentPage === 'alerts.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-bell"></i>
                <span>Safety Alerts</span>
            </a>

            <a href="activity.php" class="<?= $currentPage === 'activity.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-clock-rotate-left"></i>
                <span>Activity Log</span>
            </a>

            <a href="feedback_review.php" class="pg-nav-item <?= basename($_SERVER['PHP_SELF']) === 'feedback_review.php' ? 'active' : '' ?>">
                <i class="fa-solid fa-clipboard-check"></i>
                <span>Feedback Review</span>
            </a>

        </nav>

    </div>

    <div class="pg-sidebar-bottom">

        <div class="pg-security-card">

            <div class="pg-security-title">
                <span class="pg-status-dot"></span>
                System Online
            </div>

            <div class="pg-security-text">
                Database connected
            </div>

        </div>

        <nav class="pg-nav">

            <a href="../web/logout.php">
                <i class="fa-solid fa-right-from-bracket"></i>
                <span>Logout</span>
            </a>

        </nav>

    </div>

</aside>