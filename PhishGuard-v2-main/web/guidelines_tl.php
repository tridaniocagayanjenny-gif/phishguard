<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$pageTitle = 'Mga Gabay sa Kaligtasan';
$pageSubtitle = 'Mga simpleng paraan para makaiwas sa phishing at online scam';

$userName = $_SESSION['full_name'] ?? 'User';
$userInitial = strtoupper(substr($userName, 0, 1));

?>

<!DOCTYPE html>
<html lang="tl">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title><?= htmlspecialchars($pageTitle) ?> - PhishGuard</title>

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

</head>

<body>

<div class="pg-layout">

    <?php require_once "includes/sidebar.php"; ?>

    <main class="pg-main">

        <?php require_once "includes/topbar.php"; ?>

        <section class="pg-content">

            <div class="pg-admin-hero">

                <div class="pg-eyebrow">
                    <i class="fa-solid fa-language"></i>
                    TAGALOG SAFETY GUIDE
                </div>

                <h2>Mga Gabay sa Online Safety</h2>

                <p>
                    Alamin ang mga simpleng hakbang para maprotektahan ang iyong
                    account, pera, at personal na impormasyon laban sa phishing
                    at online scam.
                </p>

            </div>

            <div class="pg-admin-grid">

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-link"></i>
                                Mag-ingat sa mga Link
                            </h3>

                            <span>
                                Huwag basta-basta mag-click ng link.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Suriin muna ang address ng website bago ito buksan.
                            </li>

                            <li>
                                Mag-ingat sa mga link na ipinapadala ng hindi kilalang tao.
                            </li>

                            <li>
                                Huwag mag-click ng link na nagsasabing kailangan mong
                                mag-login agad o i-verify ang iyong account.
                            </li>

                            <li>
                                Kapag kahina-hinala ang link, gamitin ang PhishGuard
                                Scan Center para ito ay masuri.
                            </li>

                        </ul>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-lock"></i>
                                Protektahan ang Password
                            </h3>

                            <span>
                                Panatilihing pribado ang iyong login information.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Huwag ibigay ang iyong password sa ibang tao.
                            </li>

                            <li>
                                Gumamit ng ibang password para sa iba't ibang account.
                            </li>

                            <li>
                                Huwag ilagay ang password sa website na hindi mo
                                pinagkakatiwalaan.
                            </li>

                            <li>
                                Kung may humingi ng iyong password sa pamamagitan ng
                                message, ituring itong kahina-hinala.
                            </li>

                        </ul>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-key"></i>
                                Huwag Ibigay ang OTP
                            </h3>

                            <span>
                                Ang OTP ay para lamang sa iyo.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Huwag kailanman ibigay ang iyong OTP, PIN, o security code.
                            </li>

                            <li>
                                Hindi dapat hingin ng ibang tao ang iyong verification code.
                            </li>

                            <li>
                                Kung may tumawag o nag-message at humingi ng OTP,
                                huwag itong ibigay.
                            </li>

                            <li>
                                Huwag magmadali kahit sinabing mawawala o ma-block
                                ang iyong account.
                            </li>

                        </ul>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-wallet"></i>
                                Protektahan ang Iyong Pera
                            </h3>

                            <span>
                                Mag-ingat sa mga kahilingan tungkol sa pera.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Huwag magpadala ng pera dahil lamang sa isang
                                hindi inaasahang message.
                            </li>

                            <li>
                                I-check muna kung tunay ang recipient bago magbayad.
                            </li>

                            <li>
                                Mag-ingat sa mga pekeng GCash, Maya, bank, at
                                payment messages.
                            </li>

                            <li>
                                Huwag magtiwala agad sa mga pangakong libreng pera,
                                reward, o malaking premyo.
                            </li>

                        </ul>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-qrcode"></i>
                                Mag-ingat sa QR Code
                            </h3>

                            <span>
                                Hindi lahat ng QR code ay ligtas.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Huwag basta-basta mag-scan ng QR code mula sa
                                hindi kilalang source.
                            </li>

                            <li>
                                Tingnan kung saan ka dadalhin ng QR code bago
                                magpatuloy.
                            </li>

                            <li>
                                Mag-ingat sa QR code na humihingi ng login,
                                password, OTP, o payment information.
                            </li>

                            <li>
                                Gamitin ang PhishGuard QR Scanner kapag hindi ka
                                sigurado sa QR code.
                            </li>

                        </ul>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-comment-sms"></i>
                                Mag-ingat sa SMS at Messages
                            </h3>

                            <span>
                                Suriin muna ang sender at laman ng message.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Huwag agad maniwala sa message na nagsasabing
                                may problema ang iyong account.
                            </li>

                            <li>
                                Mag-ingat sa messages na gumagamit ng pressure
                                tulad ng "urgent" o "last chance."
                            </li>

                            <li>
                                Suriin kung tunay ang sender bago sumunod sa
                                anumang instruction.
                            </li>

                            <li>
                                Gamitin ang PhishGuard SMS Scanner kung kahina-hinala
                                ang isang message.
                            </li>

                        </ul>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-image"></i>
                                Suriin ang Screenshots
                            </h3>

                            <span>
                                Maaaring peke ang mga screenshot o resibo.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Huwag agad maniwala sa screenshot ng payment o receipt.
                            </li>

                            <li>
                                Suriin ang pangalan, halaga, petsa, at iba pang
                                detalye ng transaction.
                            </li>

                            <li>
                                Kung may kahina-hinalang link o instruction sa
                                screenshot, huwag itong sundin.
                            </li>

                            <li>
                                Maaari mong gamitin ang Image Scanner ng PhishGuard
                                para suriin ang screenshot.
                            </li>

                        </ul>

                    </div>

                </div>

                <div class="pg-card">

                    <div class="pg-card-header">

                        <div>
                            <h3>
                                <i class="fa-solid fa-triangle-exclamation"></i>
                                Kapag May Hinala Ka
                            </h3>

                            <span>
                                Huminto muna bago gumawa ng anumang aksyon.
                            </span>
                        </div>

                    </div>

                    <div class="pg-card-body">

                        <ul class="pg-guideline-list">

                            <li>
                                Huwag mag-click, mag-login, o magpadala ng pera.
                            </li>

                            <li>
                                Huwag ibigay ang password, OTP, PIN, o iba pang
                                sensitibong impormasyon.
                            </li>

                            <li>
                                Suriin ang link, QR code, image, o SMS gamit ang
                                PhishGuard.
                            </li>

                            <li>
                                Kung hindi ka sigurado, humingi muna ng tulong
                                sa isang taong pinagkakatiwalaan mo.
                            </li>

                        </ul>

                    </div>

                </div>

            </div>

        </section>

    </main>

</div>

<script src="../assets/js/app.js"></script>

</body>

</html>