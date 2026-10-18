<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$pageTitle = 'Security Scan Center';
$pageSubtitle = 'Analyze links, images, QR codes, and SMS messages';

$type = $_GET['type'] ?? 'url';

$allowedTypes = ['url', 'image', 'qr', 'sms'];

if (!in_array($type, $allowedTypes, true)) {
    $type = 'url';
}

$userName = $_SESSION['full_name'] ?? 'User';
$userInitial = strtoupper(substr($userName, 0, 1));

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Scan Center | PhishGuard</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <link
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
        rel="stylesheet"
    >

    <style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>

    <style>
        .pg-ocr-input-wrapper {
            position: relative;
            width: 100%;
        }

        .pg-ocr-input-wrapper .pg-textarea {
            width: 100%;
            min-height: 100px;
            padding: 12px 110px 12px 14px;
        }

        .pg-ocr-open-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: #4285f4;
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            -webkit-tap-highlight-color: transparent;
            box-shadow: 0 2px 6px rgba(66, 133, 244, 0.3);
            z-index: 5;
        }

        .pg-ocr-open-btn:hover {
            background: #357ae8;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(66, 133, 244, 0.4);
        }

        .pg-ocr-open-btn:active {
            transform: translateY(0);
        }

        .pg-ocr-open-btn.danger {
            background: #d93025;
            box-shadow: 0 2px 6px rgba(217, 48, 37, 0.3);
        }

        .pg-ocr-open-btn.danger:hover {
            background: #b3261e;
            box-shadow: 0 4px 12px rgba(217, 48, 37, 0.4);
        }

        .pg-ocr-open-btn.suspicious {
            background: #f59e0b;
            box-shadow: 0 2px 6px rgba(245, 158, 11, 0.3);
        }

        .pg-ocr-open-btn.suspicious:hover {
            background: #d97706;
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4);
        }

        #urlOpenWrapper {
            margin-top: 14px;
        }

        #urlOpenWrapper .pg-ocr-open-btn {
            position: static;
            width: 100%;
            height: 44px;
            justify-content: center;
            background: linear-gradient(135deg, #2563eb, #38bdf8);
            box-shadow: 0 4px 14px rgba(37, 99, 235, 0.28);
            font-size: 13px;
            padding: 0 16px;
        }

        #urlOpenWrapper .pg-ocr-open-btn:hover {
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.42);
        }

        #urlOpenWrapper .pg-ocr-open-btn.danger {
            background: linear-gradient(135deg, #dc2626, #ef4444);
            box-shadow: 0 4px 14px rgba(220, 38, 38, 0.28);
        }

        #urlOpenWrapper .pg-ocr-open-btn.danger:hover {
            box-shadow: 0 8px 20px rgba(220, 38, 38, 0.42);
        }

        #urlOpenWrapper .pg-ocr-open-btn.suspicious {
            background: linear-gradient(135deg, #d97706, #f59e0b);
            box-shadow: 0 4px 14px rgba(217, 119, 6, 0.28);
        }

        #urlOpenWrapper .pg-ocr-open-btn.suspicious:hover {
            box-shadow: 0 8px 20px rgba(217, 119, 6, 0.42);
        }

        .pg-qr-decoded-block {
            margin-top: 18px;
        }

        .pg-qr-decoded-label {
            display: block;
            margin-bottom: 8px;
            color: #cbd5e1;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }

        @media (max-width: 480px) {
            .pg-ocr-input-wrapper {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }

            .pg-ocr-input-wrapper .pg-textarea {
                padding: 12px 14px;
            }

            .pg-ocr-open-btn {
                position: static;
                align-self: flex-end;
                padding: 10px 18px;
                font-size: 14px;
            }
        }
    </style>

</head>

<body>

<div class="pg-layout">

    <?php require_once 'includes/sidebar.php'; ?>

    <main class="pg-main">

        <?php require_once 'includes/topbar.php'; ?>

        <div class="pg-content">

            <section class="pg-hero">

                <span class="pg-eyebrow">
                    <i class="fa-solid fa-radar"></i>
                    Threat Analysis
                </span>

                <h1>
                    Scan before you trust.
                </h1>

                <p>
                    Submit a suspicious link, screenshot, QR code, or SMS
                    message. PhishGuard will analyze the information and
                    provide a security risk assessment.
                </p>

            </section>

            <div class="pg-scanner-layout">

                <div>

                    <div
                        class="pg-section-label"
                        style="padding-left:4px;"
                    >
                        Scan Type
                    </div>

                    <div class="pg-scanner-tabs">

                        <button
                            type="button"
                            class="pg-scanner-tab <?= $type === 'url' ? 'active' : '' ?>"
                            data-target="urlPanel"
                        >

                            <i class="fa-solid fa-link"></i>

                            <span>
                                <strong>URL Guard</strong>
                                <small>Analyze suspicious links</small>
                            </span>

                        </button>

                        <button
                            type="button"
                            class="pg-scanner-tab <?= $type === 'image' ? 'active' : '' ?>"
                            data-target="imagePanel"
                        >

                            <i class="fa-solid fa-image"></i>

                            <span>
                                <strong>Image & OCR</strong>
                                <small>Analyze screenshots</small>
                            </span>

                        </button>

                        <button
                            type="button"
                            class="pg-scanner-tab <?= $type === 'qr' ? 'active' : '' ?>"
                            data-target="qrPanel"
                        >

                            <i class="fa-solid fa-qrcode"></i>

                            <span>
                                <strong>QR Scanner</strong>
                                <small>Analyze QR destinations</small>
                            </span>

                        </button>

                        <button
                            type="button"
                            class="pg-scanner-tab <?= $type === 'sms' ? 'active' : '' ?>"
                            data-target="smsPanel"
                        >

                            <i class="fa-solid fa-message"></i>

                            <span>
                                <strong>SMS Scanner</strong>
                                <small>Analyze sender and message</small>
                            </span>

                        </button>

                    </div>

                </div>

                <div>

                    <div
                        id="urlPanel"
                        class="pg-scanner-panel <?= $type === 'url' ? 'active' : '' ?>"
                    >

                        <div class="pg-card">

                            <div class="pg-card-header">

                                <div>

                                    <h3>
                                        <i
                                            class="fa-solid fa-link"
                                            style="color:#38bdf8;margin-right:7px;"
                                        ></i>
                                        URL Guard
                                    </h3>

                                    <p style="margin:5px 0 0;color:#64748b;font-size:10px;">
                                        Check a website before opening it.
                                    </p>

                                </div>

                                <span class="pg-badge pg-badge-safe">
                                    LIVE ANALYSIS
                                </span>

                            </div>

                            <div class="pg-card-body">

                                <form
                                    id="urlForm"
                                    onsubmit="event.preventDefault();submitPhishGuardScan(this,'../api/scan_url.php','#urlResult','#urlLoading');"
                                    autocomplete="off"
                                >

                                    <div class="pg-form-group" style="position:relative;">

                                        <label>
                                            Suspicious URL
                                        </label>

                                        <input
                                            type="url"
                                            name="url"
                                            id="urlInput"
                                            class="pg-input"
                                            placeholder="https://example.com"
                                            required
                                            autocomplete="off"
                                            spellcheck="false"
                                        >

                                        <div id="urlMiniBrowser" class="pg-mini-browser" style="display:none;"></div>

                                    </div>

                                    <button
                                        type="submit"
                                        class="pg-btn"
                                    >

                                        <i class="fa-solid fa-shield-halved"></i>

                                        Analyze URL

                                    </button>

                                </form>

                                <div
                                    id="urlOpenWrapper"
                                    style="display:none;"
                                >
                                    <button
                                        type="button"
                                        class="pg-ocr-open-btn"
                                        id="urlOpenBtn"
                                        title="Open this URL in Mini Browser"
                                    >
                                        <i class="fa-solid fa-arrow-up-right-from-square"></i>
                                        <span>Open in Mini Browser</span>
                                    </button>
                                </div>

                                <div
                                    id="urlLoading"
                                    class="pg-loading"
                                >

                                    <span class="pg-spinner"></span>

                                    PhishGuard is analyzing the URL...

                                </div>

                                <div
                                    id="urlResult"
                                    class="pg-result"
                                ></div>

                            </div>

                        </div>

                    </div>

                    <div
                        id="imagePanel"
                        class="pg-scanner-panel <?= $type === 'image' ? 'active' : '' ?>"
                    >

                        <div class="pg-card">

                            <div class="pg-card-header">

                                <div>

                                    <h3>
                                        <i
                                            class="fa-solid fa-image"
                                            style="color:#38bdf8;margin-right:7px;"
                                        ></i>
                                        Image & OCR Scanner
                                    </h3>

                                    <p style="margin:5px 0 0;color:#64748b;font-size:10px;">
                                        Detect suspicious text inside screenshots and receipts.
                                    </p>

                                </div>

                                <span class="pg-badge pg-badge-safe">
                                    OCR ANALYSIS
                                </span>

                            </div>

                            <div class="pg-card-body">

                                <form
                                    id="imageForm"
                                    enctype="multipart/form-data"
                                    onsubmit="event.preventDefault();submitPhishGuardScan(this,'../api/scan_image.php','#imageResult','#imageLoading');"
                                >

                                    <div class="pg-form-group">

                                        <label>
                                            Upload Image
                                        </label>

                                        <div
                                            class="pg-upload"
                                            id="imageUploadArea"
                                        >

                                            <input
                                                type="file"
                                                name="image"
                                                id="imageFile"
                                                accept="image/png,image/jpeg,image/jpg,image/webp"
                                                required
                                                hidden
                                            >

                                            <label
                                                for="imageFile"
                                                class="pg-upload-label"
                                            >

                                                <div class="pg-upload-icon">
                                                    <i class="fa-solid fa-cloud-arrow-up"></i>
                                                </div>

                                                <strong>
                                                    Upload screenshot or receipt
                                                </strong>

                                                <span>
                                                    PNG, JPG, JPEG, or WEBP
                                                </span>

                                            </label>

                                        </div>

                                    </div>

                                    <div
                                        id="imagePreview"
                                        class="pg-image-preview"
                                        style="display:none;"
                                    >

                                        <div class="pg-image-preview-header">

                                            <span>
                                                <i class="fa-solid fa-image"></i>
                                                Image Preview
                                            </span>

                                            <button
                                                type="button"
                                                id="removeImage"
                                                class="pg-remove-image"
                                            >

                                                <i class="fa-solid fa-xmark"></i>

                                            </button>

                                        </div>

                                        <div class="pg-image-preview-box">

                                            <img
                                                id="imagePreviewImg"
                                                src=""
                                                alt="Selected image preview"
                                            >

                                        </div>

                                        <div
                                            id="imageFileName"
                                            class="pg-image-file-name"
                                        ></div>

                                    </div>

                                    <button
                                        type="submit"
                                        class="pg-btn"
                                    >

                                        <i class="fa-solid fa-magnifying-glass"></i>

                                        Analyze Image

                                    </button>

                                </form>

                                <div
                                    id="imageLoading"
                                    class="pg-loading"
                                >

                                    <span class="pg-spinner"></span>

                                    OCR is extracting and analyzing text...

                                </div>

                                <div
                                    id="imageResult"
                                    class="pg-result"
                                ></div>

                                <div
                                    class="pg-form-group"
                                    style="margin-top:18px;"
                                >

                                    <label>
                                        Extracted OCR Text
                                    </label>

                                    <div class="pg-ocr-input-wrapper">

                                        <textarea
                                            id="ocrText"
                                            class="pg-textarea"
                                            readonly
                                            placeholder="Extracted text will appear here after scanning."
                                        ></textarea>

                                        <button
                                            type="button"
                                            class="pg-ocr-open-btn"
                                            id="ocrOpenBtn"
                                            style="display:none;"
                                            title="Open detected URL"
                                        >
                                            <i class="fa-solid fa-arrow-up-right-from-square"></i>
                                            <span>Open</span>
                                        </button>

                                    </div>

                                </div>

                            </div>

                        </div>

                    </div>

                    <div
                        id="qrPanel"
                        class="pg-scanner-panel <?= $type === 'qr' ? 'active' : '' ?>"
                    >

                        <div class="pg-card">

                            <div class="pg-card-header">

                                <div>

                                    <h3>
                                        <i
                                            class="fa-solid fa-qrcode"
                                            style="color:#38bdf8;margin-right:7px;"
                                        ></i>
                                        QR Security Scanner
                                    </h3>

                                    <p style="margin:5px 0 0;color:#64748b;font-size:10px;">
                                        Decode a QR image and analyze its destination before opening it.
                                    </p>

                                </div>

                                <span class="pg-badge pg-badge-safe">
                                    QR ANALYSIS
                                </span>

                            </div>

                            <div class="pg-card-body">

                                <form
                                    id="qrScanForm"
                                    enctype="multipart/form-data"
                                    onsubmit="event.preventDefault();analyzeQR();"
                                >

                                    <div class="pg-form-group">

                                        <label>
                                            Upload QR Code
                                        </label>

                                        <div
                                            class="pg-upload pg-qr-upload"
                                            id="qrUploadArea"
                                        >

                                            <input
                                                type="file"
                                                name="qr_image"
                                                id="qrImage"
                                                accept="image/png,image/jpeg,image/jpg,image/webp"
                                                required
                                                hidden
                                            >

                                            <label
                                                for="qrImage"
                                                class="pg-upload-label"
                                            >

                                                <div class="pg-upload-icon">
                                                    <i class="fa-solid fa-qrcode"></i>
                                                </div>

                                                <strong>
                                                    Upload QR Code Image
                                                </strong>

                                                <span>
                                                    PNG, JPG, JPEG, or WEBP
                                                </span>

                                            </label>

                                        </div>

                                    </div>

                                    <div
                                        id="qrImagePreview"
                                        class="pg-image-preview"
                                        style="display:none;"
                                    >

                                        <div class="pg-image-preview-header">

                                            <span>
                                                <i class="fa-solid fa-qrcode"></i>
                                                QR Image Preview
                                            </span>

                                            <button
                                                type="button"
                                                id="removeQR"
                                                class="pg-remove-image"
                                            >

                                                <i class="fa-solid fa-xmark"></i>

                                            </button>

                                        </div>

                                        <div class="pg-image-preview-box pg-qr-image-box">

                                            <img
                                                id="qrPreviewImg"
                                                src=""
                                                alt="QR code preview"
                                            >

                                        </div>

                                    </div>

                                    <canvas
                                        id="qrCanvas"
                                        hidden
                                    ></canvas>

                                    <div
                                        id="qrDecodedPreview"
                                        class="pg-qr-preview"
                                    >

                                        <div class="pg-qr-preview-icon">
                                            <i class="fa-solid fa-qrcode"></i>
                                        </div>

                                        <div>

                                            <strong>
                                                QR content will appear here
                                            </strong>

                                            <span>
                                                Upload an image to begin decoding.
                                            </span>

                                        </div>

                                    </div>

                                    <div
                                        class="pg-loading"
                                        id="qrLoading"
                                    >

                                        <span class="pg-spinner"></span>

                                        <div>

                                            <strong>
                                                Analyzing QR Code...
                                            </strong>

                                            <span>
                                                Decoding and checking the QR destination.
                                            </span>

                                        </div>

                                    </div>

                                    <button
                                        type="submit"
                                        class="pg-btn pg-scan-button"
                                    >

                                        <i class="fa-solid fa-shield-halved"></i>

                                        Analyze QR Code

                                    </button>

                                </form>

                                <div
                                    id="qrResult"
                                    class="pg-result"
                                ></div>

                                <div
                                    id="qrDecodedBlock"
                                    class="pg-qr-decoded-block"
                                    style="display:none;"
                                >

                                    <label class="pg-qr-decoded-label">
                                        Decoded QR Data
                                    </label>

                                    <div class="pg-ocr-input-wrapper">

                                        <textarea
                                            id="qrDecodedText"
                                            class="pg-textarea"
                                            readonly
                                            placeholder="Decoded QR data will appear here after scanning."
                                        ></textarea>

                                        <button
                                            type="button"
                                            class="pg-ocr-open-btn"
                                            id="qrOpenBtn"
                                            style="display:none;"
                                            title="Open detected URL"
                                        >
                                            <i class="fa-solid fa-arrow-up-right-from-square"></i>
                                            <span>Open</span>
                                        </button>

                                    </div>

                                </div>

                            </div>

                        </div>

                    </div>

                    <div
                        id="smsPanel"
                        class="pg-scanner-panel <?= $type === 'sms' ? 'active' : '' ?>"
                    >

                        <div class="pg-card">

                            <div class="pg-card-header">

                                <div>

                                    <h3>
                                        <i
                                            class="fa-solid fa-message"
                                            style="color:#38bdf8;margin-right:7px;"
                                        ></i>
                                        SMS Security Scanner
                                    </h3>

                                    <p style="margin:5px 0 0;color:#64748b;font-size:10px;">
                                        Analyze the sender and message for phishing and scam indicators.
                                    </p>

                                </div>

                                <span class="pg-badge pg-badge-safe">
                                    SMS ANALYSIS
                                </span>

                            </div>

                            <div class="pg-card-body">

                                <form
                                    id="smsForm"
                                    onsubmit="event.preventDefault();submitPhishGuardScan(this,'../api/sms_lookup.php','#smsResult','#smsLoading');"
                                >

                                    <div class="pg-form-group">

                                        <label>
                                            SMS Sender
                                        </label>

                                        <input
                                            type="text"
                                            name="sender"
                                            class="pg-input"
                                            placeholder="e.g. GCash, 09171234567, 2882"
                                            autocomplete="off"
                                            maxlength="100"
                                            required
                                        >

                                    </div>

                                    <div class="pg-form-group">

                                        <label>
                                            SMS Message
                                        </label>

                                        <textarea
                                            name="message"
                                            class="pg-textarea"
                                            rows="5"
                                            maxlength="5000"
                                            placeholder="Paste the suspicious SMS message here for full phishing analysis."
                                            required
                                        ></textarea>

                                    </div>

                                    <button
                                        type="submit"
                                        class="pg-btn"
                                    >

                                        <i class="fa-solid fa-shield-halved"></i>

                                        Analyze SMS

                                    </button>

                                </form>

                                <div
                                    id="smsLoading"
                                    class="pg-loading"
                                >

                                    <span class="pg-spinner"></span>

                                    Checking sender and message indicators...

                                </div>

                                <div
                                    id="smsResult"
                                    class="pg-result"
                                ></div>

                                <div
                                    id="smsDecodedBlock"
                                    class="pg-qr-decoded-block"
                                    style="display:none;"
                                >

                                    <label class="pg-qr-decoded-label">
                                        Detected URL from SMS
                                    </label>

                                    <div class="pg-ocr-input-wrapper">

                                        <textarea
                                            id="smsDetectedUrl"
                                            class="pg-textarea"
                                            readonly
                                            placeholder="URL will appear here if detected in the message."
                                        ></textarea>

                                        <button
                                            type="button"
                                            class="pg-ocr-open-btn"
                                            id="smsOpenBtn"
                                            style="display:none;"
                                            title="Open detected URL"
                                        >
                                            <i class="fa-solid fa-arrow-up-right-from-square"></i>
                                            <span>Open</span>
                                        </button>

                                    </div>

                                </div>

                            </div>

                        </div>

                    </div>

                </div>

            </div>

            <section
                class="pg-card"
                style="margin-top:20px;"
            >

                <div class="pg-card-body">

                    <div class="pg-alert">

                        <div class="pg-alert-icon">
                            <i class="fa-solid fa-circle-info"></i>
                        </div>

                        <div>

                            <h4>
                                Important security reminder
                            </h4>

                            <p>
                                A SAFE result does not guarantee that a website,
                                message, QR code, or sender is completely trustworthy.
                                Never share your password, PIN, or OTP with anyone.
                            </p>

                        </div>

                    </div>

                </div>

            </section>

            <div class="pg-footer">
                PhishGuard • AI-Powered Phishing Detection System
            </div>

        </div>

    </main>

</div>

<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"></script>

<script>
document.addEventListener('DOMContentLoaded', function () {

    const urlInput    = document.getElementById('urlInput');
    const miniBrowser = document.getElementById('urlMiniBrowser');

    if (!urlInput || !miniBrowser) return;

    let searchTimer = null;

    urlInput.addEventListener('input', function () {

        const query = urlInput.value.trim();

        clearTimeout(searchTimer);

        if (query.length < 3) {
            miniBrowser.style.display = 'none';
            miniBrowser.innerHTML = '';
            return;
        }

        searchTimer = setTimeout(function () {

            fetch('../api/url_preview.php?q=' + encodeURIComponent(query))
                .then(r => r.json())
                .then(data => {

                    if (!data.success) {
                        miniBrowser.style.display = 'none';
                        return;
                    }

                    miniBrowser.innerHTML = data.html;
                    miniBrowser.style.display = 'block';

                })
                .catch(() => {
                    miniBrowser.style.display = 'none';
                });

        }, 400);
    });

    document.addEventListener('click', function (e) {
        if (!miniBrowser.contains(e.target) && e.target !== urlInput) {
            miniBrowser.style.display = 'none';
        }
    });

    miniBrowser.addEventListener('click', function (e) {

        const item = e.target.closest('.pg-mb-item');
        if (!item) return;

        const url = item.dataset.url;

        urlInput.value = url;
        miniBrowser.style.display = 'none';

        const badge  = item.querySelector('.pg-mb-badge');
        const isOpen = badge && badge.textContent.trim().toUpperCase() === 'OPEN';

        if (isOpen) {
            const returnTo = encodeURIComponent(window.location.pathname.split('/').pop() + window.location.search);
            window.location.href = 'mini_browser.php?url=' + encodeURIComponent(url) + '&from=' + returnTo;
        }
    });

});
</script>

<script>
document.addEventListener('DOMContentLoaded', function () {

    const DANGEROUS_SITES = [
        { domain: 'malware-download.com',         reason: 'Downloads malware' },
        { domain: 'phishing-bank.com',            reason: 'Impersonates a bank' },
        { domain: 'free-bitcoin-generator.net',   reason: 'Crypto scam' },
        { domain: 'fake-login-facebook.com',      reason: 'Fake login page' },
        { domain: 'virus-total-free.com',         reason: 'Fake antivirus' },
        { domain: 'hack-tool-pro.com',            reason: 'Illegal hacking tools' },
        { domain: 'torrent-pirate-bay.com',       reason: 'Pirated content' },
        { domain: 'adult-scam-site.com',          reason: 'Adult scam' },
        { domain: 'get-rich-quick-now.biz',       reason: 'Ponzi scheme' },
        { domain: 'win-free-iphone.xyz',          reason: 'Fake giveaway' },
    ];

    const SUSPICIOUS_PATTERNS = [
        { pattern: /free.*(money|bitcoin|iphone|prize)/i,                     reason: 'Too good to be true offer' },
        { pattern: /(login|verify|account).*\.(xyz|tk|ml|ga|cf)/i,            reason: 'Suspicious domain extension' },
        { pattern: /^\d+\.\d+\.\d+\.\d+/,                                     reason: 'IP address instead of domain' },
        { pattern: /paypal|bank|secure.*-.*\./i,                              reason: 'Possible phishing' },
        { pattern: /(?:libraries|joomla|wp-content|wp-admin|administrator)/i, reason: 'Exposed system path' },
    ];

    const SHORTENER_DOMAINS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
        'ow.ly', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
        'rb.gy', 'tiny.cc', 'tr.im', 'v.gd', 'shorte.st',
        'adf.ly', 'bc.vc', 'soo.gd', 's2r.co', 'clck.ru'
    ];

    const SCAM_KEYWORDS = [
        'balance', 'cash out', 'cashout', 'claim', 'winner',
        'congrats', 'congratulations', 'prize', 'reward',
        'you won', 'free money', 'free cash', 'promo',
        'gcash', 'maya', 'paymaya', 'gotyme', 'shopee pay'
    ];

    const SUSPICIOUS_TLDS = [
        '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
        '.top', '.work', '.click', '.zip', '.online',
        '.link', '.live', '.icu', '.buzz', '.rest'
    ];

    let latestApiResult = null;

    function extractDomain(input) {
        try {
            if (!input.startsWith('http')) input = 'https://' + input;
            const url = new URL(input);
            return url.hostname.replace('www.', '').toLowerCase();
        } catch (e) {
            return input.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
        }
    }

    function extractFullUrl(input) {
        try {
            if (!input.startsWith('http')) input = 'https://' + input;
            const url = new URL(input);
            return url.href.toLowerCase();
        } catch (e) {
            return input.toLowerCase();
        }
    }

    function isShortener(domain) {
        return SHORTENER_DOMAINS.some(function (s) {
            return domain === s || domain.endsWith('.' + s);
        });
    }

    function checkDanger(domain, fullUrl) {
        const match = DANGEROUS_SITES.find(function (s) {
            return domain === s.domain || domain.endsWith('.' + s.domain);
        });
        if (match) return { level: 'danger', reason: match.reason };

        if (isShortener(domain)) {
            return {
                level: 'suspicious',
                reason: 'Shortened URL hides the real destination. Cannot verify target safely.'
            };
        }

        for (let i = 0; i < SUSPICIOUS_PATTERNS.length; i++) {
            const p = SUSPICIOUS_PATTERNS[i];
            if (p.pattern.test(domain)) {
                return { level: 'suspicious', reason: p.reason };
            }
        }

        const urlLower = (fullUrl || '').toLowerCase();

        for (let j = 0; j < SCAM_KEYWORDS.length; j++) {
            const kw = SCAM_KEYWORDS[j];
            if (urlLower.indexOf(kw) !== -1) {
                return {
                    level: 'suspicious',
                    reason: 'Contains scam bait keyword: "' + kw + '"'
                };
            }
        }

        for (let k = 0; k < SUSPICIOUS_TLDS.length; k++) {
            const tld = SUSPICIOUS_TLDS[k];
            if (domain.endsWith(tld)) {
                return {
                    level: 'suspicious',
                    reason: 'Suspicious top-level domain (' + tld + ') often used in scams'
                };
            }
        }

        return { level: 'safe', reason: 'No threats found' };
    }

    function getEffectiveDanger(url) {
        const domain  = extractDomain(url);
        const fullUrl = extractFullUrl(url);

        if (latestApiResult && latestApiResult.url) {
            const apiDomain = extractDomain(latestApiResult.url);
            if (apiDomain === domain) {
                return {
                    level: latestApiResult.verdict.toLowerCase(),
                    reason: latestApiResult.explanation || 'Flagged by PhishGuard API'
                };
            }
        }

        return checkDanger(domain, fullUrl);
    }

    const urlResultContainer = document.getElementById('urlResult');
    const urlInputEl         = document.getElementById('urlInput');

    if (urlResultContainer && window.MutationObserver) {
        const observer = new MutationObserver(function () {

            const text = (urlResultContainer.textContent || '').toUpperCase();
            const currentUrl = (urlInputEl && urlInputEl.value ? urlInputEl.value : '').trim();

            if (!currentUrl) return;

            let verdict = null;

            if (text.indexOf('DANGEROUS') !== -1) {
                verdict = 'DANGEROUS';
            } else if (text.indexOf('SUSPICIOUS') !== -1) {
                verdict = 'SUSPICIOUS';
            } else if (text.indexOf('SAFE') !== -1) {
                verdict = 'SAFE';
            }

            if (!verdict) return;

            let explanation = '';

            const reasonEl = urlResultContainer.querySelector(
                '.pg-result-reason, .pg-reason, .pg-result-text, .pg-explanation, .pg-result-message'
            );

            if (reasonEl) {
                explanation = reasonEl.textContent.trim();
            }

            if (!explanation) {
                const paras = urlResultContainer.querySelectorAll('p, span, li');
                const parts = [];
                paras.forEach(function (el) {
                    const t = el.textContent.trim();
                    if (t && t.length > 5 && t.length < 500) parts.push(t);
                });
                explanation = parts.slice(0, 4).join(' | ');
            }

            if (!explanation) {
                explanation = urlResultContainer.textContent.trim().substring(0, 400);
            }

            latestApiResult = {
                url: currentUrl,
                verdict: verdict,
                explanation: explanation
            };

            if (typeof window.updateUrlOpenButton === 'function') {
                window.updateUrlOpenButton();
            }
        });

        observer.observe(urlResultContainer, {
            childList: true,
            subtree: true,
            characterData: true
        });
    }

    function isValidUrl(text) {
        if (!text) return false;
        const cleaned = text.trim();
        if (cleaned.length < 4) return false;
        if (/\s/.test(cleaned)) return false;
        return /^[\w\-.:\/?=&%#]+$/.test(cleaned) && cleaned.includes('.');
    }

    function extractFirstUrl(text) {
        if (!text) return '';
        const lines = text.split(/\s+/).map(function (l) { return l.trim(); }).filter(Boolean);
        for (let i = 0; i < lines.length; i++) {
            if (isValidUrl(lines[i])) return lines[i];
        }
        return lines[0] || '';
    }

    function getReturnTo() {
        return encodeURIComponent(
            window.location.pathname.split('/').pop() + window.location.search
        );
    }

    function goToMiniBrowser(url, danger) {
        const level  = danger ? danger.level : 'safe';
        const reason = danger ? danger.reason : '';

        window.location.href =
            'mini_browser.php?url=' + encodeURIComponent(url) +
            '&result=' + encodeURIComponent(level.toUpperCase()) +
            '&explanation=' + encodeURIComponent(reason) +
            '&from=' + getReturnTo();
    }

    function setButtonState(btn, danger, defaultLabel) {
        btn.classList.remove('danger', 'suspicious');

        if (danger.level === 'danger') {
            btn.classList.add('danger');
            btn.innerHTML =
                '<i class="fa-solid fa-triangle-exclamation"></i><span>Open (Risky)</span>';
            btn.title = 'Dangerous: ' + danger.reason;
        } else if (danger.level === 'suspicious') {
            btn.classList.add('suspicious');
            btn.innerHTML =
                '<i class="fa-solid fa-triangle-exclamation"></i><span>Open (Careful)</span>';
            btn.title = 'Suspicious: ' + danger.reason;
        } else {
            btn.innerHTML =
                '<i class="fa-solid fa-arrow-up-right-from-square"></i><span>' + defaultLabel + '</span>';
            btn.title = 'Open in Mini Browser';
        }
    }

    const urlOpenWrapper = document.getElementById('urlOpenWrapper');
    const urlOpenBtn     = document.getElementById('urlOpenBtn');

    function updateUrlOpenButton() {
        if (!urlInputEl || !urlOpenBtn || !urlOpenWrapper) return;

        const rawText = (urlInputEl.value || '').trim();
        const url     = extractFirstUrl(rawText);

        if (!url || !isValidUrl(url)) {
            urlOpenWrapper.style.display = 'none';
            return;
        }

        const danger = getEffectiveDanger(url);

        urlOpenWrapper.style.display = 'block';
        urlOpenBtn.dataset.url    = url;
        urlOpenBtn.dataset.level  = danger.level;
        urlOpenBtn.dataset.reason = danger.reason;

        setButtonState(urlOpenBtn, danger, 'Open in Mini Browser');
    }

    window.updateUrlOpenButton = updateUrlOpenButton;

    if (urlOpenBtn) {
        urlOpenBtn.addEventListener('click', function () {
            const url = urlOpenBtn.dataset.url;
            if (!url) return;

            const danger = getEffectiveDanger(url);
            goToMiniBrowser(url, danger);
        });
    }

    if (urlInputEl) {
        urlInputEl.addEventListener('input', updateUrlOpenButton);
        urlInputEl.addEventListener('change', updateUrlOpenButton);
    }

    const ocrText    = document.getElementById('ocrText');
    const ocrOpenBtn = document.getElementById('ocrOpenBtn');

    function getOcrText() {
        if (!ocrText) return '';
        const v = (ocrText.value || '').trim();
        if (v !== '') return v;
        const t = (ocrText.textContent || '').trim();
        if (t !== '') return t;
        return (ocrText.innerHTML || '').trim();
    }

    function updateOcrOpenButton() {
        if (!ocrText || !ocrOpenBtn) return;

        const rawText = getOcrText();
        const url     = extractFirstUrl(rawText);

        if (!url || !isValidUrl(url)) {
            ocrOpenBtn.style.display = 'none';
            return;
        }

        const danger = checkDanger(extractDomain(url), extractFullUrl(url));

        ocrOpenBtn.style.display  = 'inline-flex';
        ocrOpenBtn.dataset.url    = url;
        ocrOpenBtn.dataset.level  = danger.level;
        ocrOpenBtn.dataset.reason = danger.reason;

        setButtonState(ocrOpenBtn, danger, 'Open');
    }

    window.updateOcrOpenButton = updateOcrOpenButton;

    if (ocrOpenBtn) {
        ocrOpenBtn.addEventListener('click', function () {
            const url = ocrOpenBtn.dataset.url;
            if (!url) return;
            goToMiniBrowser(url, checkDanger(extractDomain(url), extractFullUrl(url)));
        });
    }

    if (ocrText) {
        ocrText.addEventListener('input', updateOcrOpenButton);
        ocrText.addEventListener('change', updateOcrOpenButton);
    }

    const qrDecodedBlock = document.getElementById('qrDecodedBlock');
    const qrDecodedText  = document.getElementById('qrDecodedText');
    const qrOpenBtn      = document.getElementById('qrOpenBtn');

    function updateQrOpenButton() {
        if (!qrDecodedText || !qrOpenBtn || !qrDecodedBlock) return;

        const rawText = (qrDecodedText.value || '').trim();
        const url     = extractFirstUrl(rawText);

        if (!url || !isValidUrl(url)) {
            qrOpenBtn.style.display = 'none';
            return;
        }

        const danger = checkDanger(extractDomain(url), extractFullUrl(url));

        qrOpenBtn.style.display  = 'inline-flex';
        qrOpenBtn.dataset.url    = url;
        qrOpenBtn.dataset.level  = danger.level;
        qrOpenBtn.dataset.reason = danger.reason;

        setButtonState(qrOpenBtn, danger, 'Open');
    }

    window.updateQrOpenButton = updateQrOpenButton;

    if (qrOpenBtn) {
        qrOpenBtn.addEventListener('click', function () {
            const url = qrOpenBtn.dataset.url;
            if (!url) return;
            goToMiniBrowser(url, checkDanger(extractDomain(url), extractFullUrl(url)));
        });
    }

    if (qrDecodedText) {
        qrDecodedText.addEventListener('input', updateQrOpenButton);
        qrDecodedText.addEventListener('change', updateQrOpenButton);
    }

    const smsDecodedBlock = document.getElementById('smsDecodedBlock');
    const smsDetectedUrl  = document.getElementById('smsDetectedUrl');
    const smsOpenBtn      = document.getElementById('smsOpenBtn');
    const smsResultEl     = document.getElementById('smsResult');

    function updateSmsOpenButton() {
        if (!smsDetectedUrl || !smsOpenBtn || !smsDecodedBlock) return;

        const rawText = (smsDetectedUrl.value || '').trim();
        const url     = extractFirstUrl(rawText);

        if (!url || !isValidUrl(url)) {
            smsOpenBtn.style.display = 'none';
            return;
        }

        const danger = checkDanger(extractDomain(url), extractFullUrl(url));

        smsOpenBtn.style.display  = 'inline-flex';
        smsOpenBtn.dataset.url    = url;
        smsOpenBtn.dataset.level  = danger.level;
        smsOpenBtn.dataset.reason = danger.reason;

        setButtonState(smsOpenBtn, danger, 'Open');
    }

    window.updateSmsOpenButton = updateSmsOpenButton;

    if (smsOpenBtn) {
        smsOpenBtn.addEventListener('click', function () {
            const url = smsOpenBtn.dataset.url;
            if (!url) return;
            goToMiniBrowser(url, checkDanger(extractDomain(url), extractFullUrl(url)));
        });
    }

    if (smsDetectedUrl) {
        smsDetectedUrl.addEventListener('input', updateSmsOpenButton);
        smsDetectedUrl.addEventListener('change', updateSmsOpenButton);
    }

    const qrResultContainer = document.getElementById('qrResult');

    if (qrResultContainer && window.MutationObserver) {
        const qrObserver = new MutationObserver(function () {
            const decodedEl = qrResultContainer.querySelector('.pg-decoded-data div');

            if (decodedEl && decodedEl.textContent.trim() !== '') {
                const decodedValue = decodedEl.textContent.trim();

                if (qrDecodedBlock && qrDecodedText && qrDecodedText.value !== decodedValue) {
                    qrDecodedBlock.style.display = 'block';
                    qrDecodedText.value = decodedValue;
                    updateQrOpenButton();
                }
            }
        });

        qrObserver.observe(qrResultContainer, {
            childList: true,
            subtree: true,
            characterData: true
        });
    }

    if (smsResultEl && window.MutationObserver) {
        const smsObserver = new MutationObserver(function () {

            const textContent = smsResultEl.textContent || '';

            const urlMatch =
                textContent.match(/https?:\/\/[^\s<>"'\)\]]+/i) ||
                textContent.match(/\b[a-z0-9][a-z0-9\-]{1,}\.(?:com|net|org|ph|io|co|ly|cc|me|info|xyz|tk|ml|ga|cf|gq|top|work|click|zip|ua|ru|cn|biz|online|site|store|app)(?:\/[^\s<>"'\)\]]*)?/i);

            if (urlMatch && urlMatch[0]) {
                const detected = urlMatch[0].replace(/[.,;:!?)]+$/, '');

                if (smsDecodedBlock && smsDetectedUrl && smsDetectedUrl.value !== detected) {
                    smsDecodedBlock.style.display = 'block';
                    smsDetectedUrl.value = detected;
                    updateSmsOpenButton();
                }
            } else {
                if (smsDecodedBlock) {
                    smsDecodedBlock.style.display = 'none';
                }
            }
        });

        smsObserver.observe(smsResultEl, {
            childList: true,
            subtree: true,
            characterData: true
        });
    }

    setInterval(function () {
        updateUrlOpenButton();
        updateOcrOpenButton();
        updateQrOpenButton();
        updateSmsOpenButton();
    }, 500);

    updateUrlOpenButton();
    updateOcrOpenButton();
    updateQrOpenButton();
    updateSmsOpenButton();

});
</script>

<script src="../assets/js/app.js"></script>
</body>
</html>