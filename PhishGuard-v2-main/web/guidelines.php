<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$pageTitle = 'Safety Guidelines';
$pageSubtitle = 'Practical tips for staying safe from online scams';

require_once '../db.php';

$userName = $_SESSION['full_name'] ?? 'User';
$userInitial = strtoupper(substr($userName, 0, 1));

$alerts = [];

try {
    $stmt = $pdo->query("
        SELECT id, title, message, created_at
        FROM safety_alerts
        WHERE is_active = 1
        ORDER BY created_at DESC
        LIMIT 5
    ");

    $alerts = $stmt->fetchAll();
} catch (PDOException $e) {
    $alerts = [];
}

?>
<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Safety Guidelines | PhishGuard</title>

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

</head>

<body>

<div class="pg-layout">

    <?php require_once 'includes/sidebar.php'; ?>

    <main class="pg-main">

        <?php require_once 'includes/topbar.php'; ?>

        <section class="pg-content">

            <div class="pg-hero pg-guideline-hero">

                <div>

                    <div class="pg-eyebrow">
                        <i class="fa-solid fa-shield-heart"></i>
                        PHISHGUARD FOR FILIPINOS
                    </div>

                    <h1>Think Before You Click.</h1>

                    <p>
                        Scammers can use fake websites, messages, QR codes,
                        screenshots, and social-media accounts to trick users.
                        Learn the warning signs and protect your information.
                    </p>

                </div>

                <div class="pg-guideline-hero-icon">
                    <i class="fa-solid fa-user-shield"></i>
                </div>

            </div>

            <div class="pg-guideline-grid">

                <article class="pg-guide-card">

                    <div class="pg-guide-icon">
                        <i class="fa-solid fa-link"></i>
                    </div>

                    <div class="pg-guide-number">01</div>

                    <h3>Check Links Before Clicking</h3>

                    <p>
                        Huwag agad mag-click ng links mula sa unknown
                        messages, comments, emails, or social-media accounts.
                    </p>

                    <ul>
                        <li>Check the actual domain name.</li>
                        <li>Be careful with shortened links.</li>
                        <li>Watch for unusual spelling.</li>
                        <li>Scan suspicious links with PhishGuard.</li>
                    </ul>

                </article>

                <article class="pg-guide-card">

                    <div class="pg-guide-icon">
                        <i class="fa-solid fa-mobile-screen-button"></i>
                    </div>

                    <div class="pg-guide-number">02</div>

                    <h3>Protect Your GCash & Maya</h3>

                    <p>
                        Never give your OTP, MPIN, password, or recovery
                        information to another person.
                    </p>

                    <ul>
                        <li>Never share your OTP.</li>
                        <li>Do not follow suspicious payment instructions.</li>
                        <li>Verify unexpected requests.</li>
                        <li>Use official applications and websites.</li>
                    </ul>

                </article>

                <article class="pg-guide-card">

                    <div class="pg-guide-icon">
                        <i class="fa-solid fa-qrcode"></i>
                    </div>

                    <div class="pg-guide-number">03</div>

                    <h3>Be Careful With QR Codes</h3>

                    <p>
                        A QR code can redirect you to a website or payment
                        destination that you did not expect.
                    </p>

                    <ul>
                        <li>Check where the QR code leads.</li>
                        <li>Don't scan random QR stickers.</li>
                        <li>Confirm the recipient before paying.</li>
                        <li>Use PhishGuard for suspicious QR images.</li>
                    </ul>

                </article>

                <article class="pg-guide-card">

                    <div class="pg-guide-icon">
                        <i class="fa-solid fa-comment-sms"></i>
                    </div>

                    <div class="pg-guide-number">04</div>

                    <h3>Watch Out for Fake SMS</h3>

                    <p>
                        Scammers may impersonate banks, delivery services,
                        government agencies, or online platforms.
                    </p>

                    <ul>
                        <li>Don't trust messages because of a familiar name.</li>
                        <li>Don't click urgent payment links.</li>
                        <li>Verify through official channels.</li>
                        <li>Check suspicious senders with PhishGuard.</li>
                    </ul>

                </article>

                <article class="pg-guide-card">

                    <div class="pg-guide-icon">
                        <i class="fa-solid fa-building-columns"></i>
                    </div>

                    <div class="pg-guide-number">05</div>

                    <h3>Online Banking Safety</h3>

                    <p>
                        Banks will not normally ask you to disclose sensitive
                        authentication information through random messages.
                    </p>

                    <ul>
                        <li>Use the official banking application.</li>
                        <li>Don't save passwords on public computers.</li>
                        <li>Enable available security features.</li>
                        <li>Contact your bank through official channels.</li>
                    </ul>

                </article>

                <article class="pg-guide-card">

                    <div class="pg-guide-icon">
                        <i class="fa-solid fa-gift"></i>
                    </div>

                    <div class="pg-guide-number">06</div>

                    <h3>Beware of Fake Promos</h3>

                    <p>
                        Free prizes, giveaways, job offers, investment
                        opportunities, and rewards can be used as bait.
                    </p>

                    <ul>
                        <li>Question offers that seem too good to be true.</li>
                        <li>Don't pay unexpected processing fees.</li>
                        <li>Verify the organization independently.</li>
                        <li>Don't provide sensitive information to claim a prize.</li>
                    </ul>

                </article>

            </div>

            <div class="pg-grid-2">

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>Quick Scam Checklist</h3>
                            <span>Ask yourself these questions</span>
                        </div>

                        <i class="fa-solid fa-list-check pg-card-header-icon"></i>

                    </div>

                    <div class="pg-card-body">

                        <div class="pg-checklist">

                            <div>
                                <i class="fa-solid fa-circle-check"></i>
                                <span>
                                    Is the sender someone I actually know?
                                </span>
                            </div>

                            <div>
                                <i class="fa-solid fa-circle-check"></i>
                                <span>
                                    Am I being pressured to act immediately?
                                </span>
                            </div>

                            <div>
                                <i class="fa-solid fa-circle-check"></i>
                                <span>
                                    Is someone asking for an OTP or password?
                                </span>
                            </div>

                            <div>
                                <i class="fa-solid fa-circle-check"></i>
                                <span>
                                    Does the link belong to the expected organization?
                                </span>
                            </div>

                            <div>
                                <i class="fa-solid fa-circle-check"></i>
                                <span>
                                    Can I verify this request through an official channel?
                                </span>
                            </div>

                        </div>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>If You Suspect a Scam</h3>
                            <span>Stay calm and protect your account</span>
                        </div>

                        <i class="fa-solid fa-triangle-exclamation pg-card-header-icon"></i>

                    </div>

                    <div class="pg-card-body">

                        <div class="pg-action-list">

                            <div>
                                <span class="pg-action-number">1</span>

                                <div>
                                    <strong>Stop</strong>
                                    <p>Don't continue the conversation or transaction.</p>
                                </div>
                            </div>

                            <div>
                                <span class="pg-action-number">2</span>

                                <div>
                                    <strong>Don't share information</strong>
                                    <p>Never provide OTPs, passwords, or PINs.</p>
                                </div>
                            </div>

                            <div>
                                <span class="pg-action-number">3</span>

                                <div>
                                    <strong>Verify independently</strong>
                                    <p>Contact the organization through its official channel.</p>
                                </div>
                            </div>

                            <div>
                                <span class="pg-action-number">4</span>

                                <div>
                                    <strong>Scan suspicious content</strong>
                                    <p>
                                        Use PhishGuard to analyze links, images,
                                        QR codes, or SMS senders.
                                    </p>
                                </div>
                            </div>

                        </div>

                    </div>

                </div>

            </div>

            <?php if ($alerts): ?>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>Security Alerts</h3>
                            <span>Latest safety reminders</span>
                        </div>

                        <i class="fa-solid fa-bell pg-card-header-icon"></i>

                    </div>

                    <div class="pg-card-body">

                        <div class="pg-guideline-alerts">

                            <?php foreach ($alerts as $alert): ?>

                                <div class="pg-guideline-alert">

                                    <div class="pg-alert-icon">
                                        <i class="fa-solid fa-shield-halved"></i>
                                    </div>

                                    <div>

                                        <strong>
                                            <?= htmlspecialchars($alert['title']) ?>
                                        </strong>

                                        <p>
                                            <?= htmlspecialchars($alert['message']) ?>
                                        </p>

                                    </div>

                                </div>

                            <?php endforeach; ?>

                        </div>

                    </div>

                </div>

            <?php endif; ?>

            <div class="pg-guideline-bottom">

                <div>

                    <i class="fa-solid fa-shield-halved"></i>

                    <div>
                        <strong>When in doubt, don't click.</strong>

                        <span>
                            Verify first. Protect your account and personal information.
                        </span>
                    </div>

                </div>

                <a href="scanner.php" class="pg-btn">
                    <i class="fa-solid fa-radar"></i>
                    Scan Something
                </a>

            </div>

        </section>

    </main>

</div>

<script src="../assets/js/app.js"></script>

</body>
</html>