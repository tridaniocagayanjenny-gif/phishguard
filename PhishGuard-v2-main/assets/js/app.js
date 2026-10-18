document.addEventListener('DOMContentLoaded', function () {
    initScannerTabs();
    initImagePreview();
    initQRScanner();
    initMobileMenu();
    initFormProtection();
});

function initScannerTabs() {
    const tabs = document.querySelectorAll('.pg-scanner-tab');
    const panels = document.querySelectorAll('.pg-scanner-panel');

    if (!tabs.length || !panels.length) {
        return;
    }

    function activatePanel(target, updateUrl) {
        if (updateUrl === undefined) {
            updateUrl = true;
        }

        tabs.forEach(function (tab) {
            tab.classList.toggle('active', tab.dataset.target === target);
        });

        panels.forEach(function (panel) {
            panel.classList.toggle('active', panel.id === target);
        });

        if (updateUrl) {
            const typeMap = {
                urlPanel: 'url',
                imagePanel: 'image',
                qrPanel: 'qr',
                smsPanel: 'sms'
            };

            const type = typeMap[target];

            if (type) {
                const url = new URL(window.location.href);
                url.searchParams.set('type', type);
                window.history.replaceState({}, '', url.toString());
            }
        }
    }

    tabs.forEach(function (tab) {
        tab.addEventListener('click', function () {
            activatePanel(this.dataset.target);
        });
    });

    const currentType = new URLSearchParams(window.location.search).get('type');

    const currentPanel = {
        url: 'urlPanel',
        image: 'imagePanel',
        qr: 'qrPanel',
        sms: 'smsPanel'
    }[currentType];

    if (currentPanel) {
        activatePanel(currentPanel, false);
    }
}

function initImagePreview() {
    const imageFile = document.getElementById('imageFile');
    const imageUploadArea = document.getElementById('imageUploadArea');
    const imagePreview = document.getElementById('imagePreview');
    const imagePreviewImg = document.getElementById('imagePreviewImg');
    const imageFileName = document.getElementById('imageFileName');
    const removeImage = document.getElementById('removeImage');

    if (!imageFile) {
        return;
    }

    imageFile.addEventListener('change', function () {
        const file = this.files && this.files[0];

        if (!file) {
            return;
        }

        if (!isValidImage(file)) {
            showClientError(
                'imageResult',
                'Invalid Image',
                'Please select a PNG, JPG, JPEG, or WEBP image.'
            );

            this.value = '';
            return;
        }

        if (file.size > 10 * 1024 * 1024) {
            showClientError(
                'imageResult',
                'Image Too Large',
                'Please select an image smaller than 10 MB.'
            );

            this.value = '';
            return;
        }

        const reader = new FileReader();

        reader.onload = function (event) {
            if (imagePreviewImg) {
                imagePreviewImg.src = event.target.result;
            }

            if (imageFileName) {
                imageFileName.textContent = file.name;
            }

            if (imageUploadArea) {
                imageUploadArea.style.display = 'none';
            }

            if (imagePreview) {
                imagePreview.style.display = 'block';
            }
        };

        reader.onerror = function () {
            showClientError(
                'imageResult',
                'Preview Error',
                'The selected image could not be previewed.'
            );
        };

        reader.readAsDataURL(file);
    });

    if (removeImage) {
        removeImage.addEventListener('click', function () {
            resetImageInput(
                imageFile,
                imageUploadArea,
                imagePreview,
                imagePreviewImg,
                imageFileName
            );

            const imageResult = document.getElementById('imageResult');

            if (imageResult) {
                imageResult.innerHTML = '';
            }

            const ocrText = document.getElementById('ocrText');

            if (ocrText) {
                ocrText.value = '';
            }
        });
    }
}

function initQRScanner() {
    const qrImage = document.getElementById('qrImage');
    const qrUploadArea = document.getElementById('qrUploadArea');
    const qrImagePreview = document.getElementById('qrImagePreview');
    const qrPreviewImg = document.getElementById('qrPreviewImg');
    const removeQR = document.getElementById('removeQR');
    const qrResult = document.getElementById('qrResult');
    const qrLoading = document.getElementById('qrLoading');
    const qrDecodedPreview = document.getElementById('qrDecodedPreview');
    const qrCanvas = document.getElementById('qrCanvas');

    if (!qrImage) {
        return;
    }

    qrImage.addEventListener('change', function () {
        const file = this.files && this.files[0];

        if (!file) {
            return;
        }

        if (!isValidImage(file)) {
            showQRResult(
                'danger',
                'INVALID IMAGE',
                'Please upload a PNG, JPG, JPEG, or WEBP QR image.'
            );

            this.value = '';
            return;
        }

        if (file.size > 10 * 1024 * 1024) {
            showQRResult(
                'danger',
                'IMAGE TOO LARGE',
                'Please upload a QR image smaller than 10 MB.'
            );

            this.value = '';
            return;
        }

        const reader = new FileReader();

        reader.onload = function (event) {
            if (qrPreviewImg) {
                qrPreviewImg.src = event.target.result;
            }

            if (qrUploadArea) {
                qrUploadArea.style.display = 'none';
            }

            if (qrImagePreview) {
                qrImagePreview.style.display = 'block';
            }

            if (qrDecodedPreview) {
                qrDecodedPreview.innerHTML = `
                    <div class="pg-qr-preview-icon">
                        <i class="fa-solid fa-qrcode"></i>
                    </div>

                    <div>
                        <strong>QR image selected</strong>
                        <span>Click Analyze QR Code to scan the image.</span>
                    </div>
                `;
            }

            if (qrResult) {
                qrResult.innerHTML = '';
            }
        };

        reader.onerror = function () {
            showQRResult(
                'danger',
                'PREVIEW ERROR',
                'The QR image could not be previewed.'
            );
        };

        reader.readAsDataURL(file);
    });

    if (removeQR) {
        removeQR.addEventListener('click', function () {
            qrImage.value = '';

            if (qrPreviewImg) {
                qrPreviewImg.src = '';
            }

            if (qrImagePreview) {
                qrImagePreview.style.display = 'none';
            }

            if (qrUploadArea) {
                qrUploadArea.style.display = 'block';
            }

            if (qrResult) {
                qrResult.innerHTML = '';
            }

            if (qrDecodedPreview) {
                qrDecodedPreview.innerHTML = `
                    <div class="pg-qr-preview-icon">
                        <i class="fa-solid fa-qrcode"></i>
                    </div>

                    <div>
                        <strong>QR content will appear here</strong>
                        <span>Upload an image to begin decoding.</span>
                    </div>
                `;
            }
        });
    }

    window.analyzeQR = async function () {
        if (!qrImage.files || !qrImage.files[0]) {
            showQRResult(
                'danger',
                'NO QR IMAGE',
                'Please select a QR code image first.'
            );

            return;
        }

        if (typeof jsQR === 'undefined') {
            showQRResult(
                'danger',
                'QR SCANNER UNAVAILABLE',
                'The QR scanning library was not loaded. Refresh the page and try again.'
            );

            return;
        }

        if (qrLoading) {
            qrLoading.style.display = 'flex';
        }

        if (qrResult) {
            qrResult.innerHTML = '';
        }

        if (qrDecodedPreview) {
            qrDecodedPreview.innerHTML = `
                <div class="pg-qr-preview-icon">
                    <i class="fa-solid fa-spinner fa-spin"></i>
                </div>

                <div>
                    <strong>Reading QR code...</strong>
                    <span>Please wait while PhishGuard decodes the image.</span>
                </div>
            `;
        }

        const file = qrImage.files[0];

        try {
            const image = await loadImage(file);

            let width = image.naturalWidth;
            let height = image.naturalHeight;

            if (!width || !height) {
                throw new Error('The QR image has invalid dimensions.');
            }

            const maxSize = 2000;

            if (width > maxSize || height > maxSize) {
                const scale = Math.min(maxSize / width, maxSize / height);
                width = Math.max(1, Math.floor(width * scale));
                height = Math.max(1, Math.floor(height * scale));
            }

            if (!qrCanvas) {
                throw new Error('QR canvas is missing from scanner.php.');
            }

            qrCanvas.width = width;
            qrCanvas.height = height;

            const context = qrCanvas.getContext('2d', { willReadFrequently: true });

            if (!context) {
                throw new Error('The browser could not create a QR image reader.');
            }

            context.clearRect(0, 0, width, height);
            context.drawImage(image, 0, 0, width, height);

            let code = decodeQRCode(context, width, height);

            if (!code) {
                code = await tryAlternativeQRScans(image, qrCanvas, context);
            }

            if (!code || !code.data) {
                if (qrLoading) {
                    qrLoading.style.display = 'none';
                }

                if (qrDecodedPreview) {
                    qrDecodedPreview.innerHTML = `
                        <div class="pg-qr-preview-icon">
                            <i class="fa-solid fa-triangle-exclamation"></i>
                        </div>

                        <div>
                            <strong>QR code not detected</strong>
                            <span>Use a clear, straight, high-resolution QR image.</span>
                        </div>
                    `;
                }

                showQRResult(
                    'suspicious',
                    'NO QR DETECTED',
                    'PhishGuard could not find a readable QR code in this image. Try cropping the QR code and uploading it again.'
                );

                return;
            }

            const decodedData = String(code.data).trim();

            if (!decodedData) {
                throw new Error('The QR code was detected, but it contains no readable data.');
            }

            if (qrDecodedPreview) {
                qrDecodedPreview.innerHTML = `
                    <div class="pg-qr-preview-icon">
                        <i class="fa-solid fa-circle-check"></i>
                    </div>

                    <div>
                        <strong>QR code detected</strong>
                        <span>Sending decoded content for security analysis...</span>
                    </div>
                `;
            }

            const formData = new FormData();
            formData.append('decoded_data', decodedData);

            const response = await fetch(
                '../api/scan_qr.php',
                {
                    method: 'POST',
                    body: formData,
                    credentials: 'same-origin',
                    headers: { Accept: 'application/json' }
                }
            );

            const responseText = await response.text();

            console.log('PhishGuard QR API status:', response.status);
            console.log('PhishGuard QR API response:', responseText);

            let data;

            try {
                data = JSON.parse(responseText);
            } catch (error) {
                throw new Error('The QR server returned an invalid response. Check scan_qr.php for PHP errors.');
            }

            if (!response.ok || data.error) {
                throw new Error(data.error || 'The QR security analysis failed.');
            }

            if (qrLoading) {
                qrLoading.style.display = 'none';
            }

            const result = String(data.result || 'SAFE').toUpperCase();
            const score = normalizeScore(data.risk_score);
            const explanation = data.explanation || 'No additional information was provided.';
            const resultClass = getResultClass(result);

            if (qrDecodedPreview) {
                qrDecodedPreview.innerHTML = `
                    <div class="pg-qr-preview-icon">
                        <i class="fa-solid fa-circle-check"></i>
                    </div>

                    <div>
                        <strong>QR analysis completed</strong>
                        <span>PhishGuard successfully analyzed the QR content.</span>
                    </div>
                `;
            }

            if (qrResult) {
                let qrPreviewButton = '';

                if (decodedData && /^https?:\/\//i.test(decodedData.trim())) {
                    const cleanUrl = decodedData.trim();
                    const encodedUrl = encodeURIComponent(cleanUrl);
                    const encodedResult = encodeURIComponent(result);
                    const encodedExp = encodeURIComponent(explanation);
                    const encodedFrom = encodeURIComponent('scanner.php?type=qr');

                    qrPreviewButton = `
                        <div style="margin-top:14px;">
                            <a href="mini_browser.php?url=${encodedUrl}&result=${encodedResult}&explanation=${encodedExp}&from=${encodedFrom}"
                               class="pg-btn"
                               style="text-decoration:none;display:inline-flex;">
                                <i class="fa-solid fa-eye"></i>
                                Preview Page Content
                            </a>
                        </div>
                    `;
                }

                qrResult.innerHTML = `
                    <div class="pg-result-card ${resultClass}">

                        <div class="pg-result-header">

                            <div>
                                <span class="pg-result-label">QR ANALYSIS RESULT</span>
                                <h3>${escapeHtml(result)}</h3>
                            </div>

                            <div class="pg-risk-score">${score}%</div>

                        </div>

                        <div class="pg-result-explanation">
                            ${escapeHtml(explanation)}
                        </div>

                        <div class="pg-result-saved">
                            <i class="fa-solid fa-circle-check"></i>
                            Scan automatically saved to Recent Scans and Scan History.
                        </div>

                        <div class="pg-decoded-data">
                            <span>Decoded QR Data</span>
                            <div>${escapeHtml(decodedData)}</div>
                        </div>

                        ${qrPreviewButton}

                    </div>
                `;
            }

        } catch (error) {
            console.error('PhishGuard QR error:', error);

            if (qrLoading) {
                qrLoading.style.display = 'none';
            }

            showQRResult(
                'danger',
                'SCAN ERROR',
                error.message || 'An unexpected QR scanning error occurred.'
            );
        }
    };
}

function decodeQRCode(context, width, height) {
    try {
        const imageData = context.getImageData(0, 0, width, height);

        return jsQR(
            imageData.data,
            imageData.width,
            imageData.height,
            { inversionAttempts: 'attemptBoth' }
        );
    } catch (error) {
        console.error('QR decoding error:', error);
        return null;
    }
}

async function tryAlternativeQRScans(image, canvas, context) {
    const attempts = [
        { scale: 1, flip: false },
        { scale: 1.5, flip: false },
        { scale: 2, flip: false },
        { scale: 1, flip: true }
    ];

    for (const attempt of attempts) {
        try {
            let width = Math.floor(image.naturalWidth * attempt.scale);
            let height = Math.floor(image.naturalHeight * attempt.scale);

            const maxSize = 2500;

            if (width > maxSize || height > maxSize) {
                const ratio = Math.min(maxSize / width, maxSize / height);
                width = Math.floor(width * ratio);
                height = Math.floor(height * ratio);
            }

            canvas.width = width;
            canvas.height = height;

            context.save();
            context.clearRect(0, 0, width, height);

            if (attempt.flip) {
                context.translate(width, 0);
                context.scale(-1, 1);
            }

            context.drawImage(image, 0, 0, width, height);
            context.restore();

            const imageData = context.getImageData(0, 0, width, height);

            const result = jsQR(
                imageData.data,
                width,
                height,
                { inversionAttempts: 'attemptBoth' }
            );

            if (result) {
                return result;
            }

        } catch (error) {
            console.warn('Alternative QR scan failed:', error);
        }
    }

    return null;
}

function loadImage(file) {
    return new Promise(function (resolve, reject) {
        const image = new Image();
        const objectUrl = URL.createObjectURL(file);

        image.onload = function () {
            URL.revokeObjectURL(objectUrl);
            resolve(image);
        };

        image.onerror = function () {
            URL.revokeObjectURL(objectUrl);
            reject(new Error('Unable to load the selected QR image.'));
        };

        image.src = objectUrl;
    });
}

function submitPhishGuardScan(form, apiUrl, resultSelector, loadingSelector) {
    if (!form) {
        return;
    }

    if (form.dataset.scanning === 'true') {
        return;
    }

    const resultElement = document.querySelector(resultSelector);
    const loadingElement = document.querySelector(loadingSelector);

    if (!resultElement || !loadingElement) {
        return;
    }

    const formData = new FormData(form);

    form.dataset.scanning = 'true';
    loadingElement.style.display = 'flex';
    resultElement.innerHTML = '';

    const submitButton = form.querySelector('button[type="submit"]');

    setButtonLoading(submitButton, true);

    fetch(
        apiUrl,
        {
            method: 'POST',
            body: formData,
            credentials: 'same-origin',
            headers: { Accept: 'application/json' }
        }
    )
        .then(async function (response) {
            const rawResponse = await response.text();

            console.log('PhishGuard API status:', response.status);
            console.log('PhishGuard API response:', rawResponse);

            let data;

            try {
                data = JSON.parse(rawResponse);
            } catch (error) {
                throw new Error('The server returned an invalid response.');
            }

            if (!response.ok || data.error) {
                throw new Error(data.error || 'The scan could not be completed.');
            }

            return data;
        })
        .then(function (data) {
            const result = String(data.result || 'SAFE').toUpperCase();
            const score = normalizeScore(data.risk_score);
            const explanation = data.explanation || 'No additional information available.';
            const resultClass = getResultClass(result);

            loadingElement.style.display = 'none';

            const currentScannerType =
                new URLSearchParams(window.location.search).get('type') || 'url';

            const fromParam = 'scanner.php?type=' + currentScannerType;

            const previewUrl = data.detected_url || data.url || null;

            let previewButton = '';

            if (previewUrl && /^https?:\/\//i.test(previewUrl)) {
                const encodedUrl = encodeURIComponent(previewUrl);
                const encodedResult = encodeURIComponent(result);
                const encodedExp = encodeURIComponent(explanation);
                const encodedFrom = encodeURIComponent(fromParam);

                previewButton = `
                    <div style="margin-top:14px;">
                        <a href="mini_browser.php?url=${encodedUrl}&result=${encodedResult}&explanation=${encodedExp}&from=${encodedFrom}"
                           class="pg-btn"
                           style="text-decoration:none;display:inline-flex;">
                            <i class="fa-solid fa-eye"></i>
                            Preview Page Content
                        </a>
                    </div>
                `;
            }

            resultElement.innerHTML = `
                <div class="pg-result-card ${resultClass}">

                    <div class="pg-result-header">

                        <div>
                            <span class="pg-result-label">ANALYSIS RESULT</span>
                            <h3>${escapeHtml(result)}</h3>
                        </div>

                        <div class="pg-risk-score">${score}%</div>

                    </div>

                    <div class="pg-result-explanation">
                        ${escapeHtml(explanation)}
                    </div>

                    <div class="pg-result-saved">
                        <i class="fa-solid fa-circle-check"></i>
                        Scan automatically saved to Recent Scans and Scan History.
                    </div>

                    ${previewButton}

                </div>
            `;

            const ocrText = document.getElementById('ocrText');

            if (data.ocr_text && ocrText) {
                ocrText.value = data.ocr_text;
            }
        })
        .catch(function (error) {
            console.error('PhishGuard scan error:', error);

            loadingElement.style.display = 'none';

            resultElement.innerHTML = `
                <div class="pg-result-card danger">

                    <div class="pg-result-header">
                        <div>
                            <span class="pg-result-label">SCAN ERROR</span>
                            <h3>ERROR</h3>
                        </div>
                    </div>

                    <div class="pg-result-explanation">
                        ${escapeHtml(error.message || 'Unable to complete the scan.')}
                    </div>

                </div>
            `;
        })
        .finally(function () {
            form.dataset.scanning = 'false';
            setButtonLoading(submitButton, false);
        });
}

function initFormProtection() {
    const forms = document.querySelectorAll('form');

    forms.forEach(function (form) {
        form.addEventListener('submit', function () {
            if (this.id === 'qrScanForm') {
                return;
            }
        });
    });
}

function initMobileMenu() {
    const button = document.getElementById('pgMobileMenu');
    const sidebar = document.querySelector('.pg-sidebar');

    if (!button || !sidebar) {
        return;
    }

    button.addEventListener('click', function () {
        sidebar.classList.toggle('open');
    });

    document.addEventListener('click', function (event) {
        if (window.innerWidth > 900) {
            return;
        }

        if (
            sidebar.classList.contains('open') &&
            !sidebar.contains(event.target) &&
            !button.contains(event.target)
        ) {
            sidebar.classList.remove('open');
        }
    });
}

function resetImageInput(input, uploadArea, preview, previewImage, fileName) {
    if (input) {
        input.value = '';
    }

    if (previewImage) {
        previewImage.src = '';
    }

    if (fileName) {
        fileName.textContent = '';
    }

    if (preview) {
        preview.style.display = 'none';
    }

    if (uploadArea) {
        uploadArea.style.display = 'block';
    }
}

function isValidImage(file) {
    const allowedTypes = [
        'image/png',
        'image/jpeg',
        'image/jpg',
        'image/webp'
    ];

    return allowedTypes.includes(file.type);
}

function getResultClass(result) {
    if (result === 'DANGEROUS') {
        return 'danger';
    }

    if (result === 'SUSPICIOUS') {
        return 'suspicious';
    }

    return 'safe';
}

function normalizeScore(score) {
    const number = Number(score);

    if (!Number.isFinite(number)) {
        return 0;
    }

    return Math.max(0, Math.min(100, Math.round(number)));
}

function setButtonLoading(button, loading) {
    if (!button) {
        return;
    }

    if (loading) {
        if (!button.dataset.originalHtml) {
            button.dataset.originalHtml = button.innerHTML;
        }

        button.disabled = true;

        button.innerHTML = `
            <i class="fa-solid fa-spinner fa-spin"></i>
            Analyzing...
        `;
    } else {
        button.disabled = false;

        if (button.dataset.originalHtml) {
            button.innerHTML = button.dataset.originalHtml;
        }
    }
}

function showQRResult(type, title, message) {
    const qrResult = document.getElementById('qrResult');
    const qrLoading = document.getElementById('qrLoading');

    if (qrLoading) {
        qrLoading.style.display = 'none';
    }

    if (!qrResult) {
        return;
    }

    qrResult.innerHTML = `
        <div class="pg-result-card ${type}">

            <div class="pg-result-header">
                <div>
                    <span class="pg-result-label">QR ANALYSIS RESULT</span>
                    <h3>${escapeHtml(title)}</h3>
                </div>
            </div>

            <div class="pg-result-explanation">
                ${escapeHtml(message)}
            </div>

        </div>
    `;
}

function showClientError(resultId, title, message) {
    const element = document.getElementById(resultId);

    if (!element) {
        return;
    }

    element.innerHTML = `
        <div class="pg-result-card danger">

            <div class="pg-result-header">
                <div>
                    <span class="pg-result-label">INPUT ERROR</span>
                    <h3>${escapeHtml(title)}</h3>
                </div>
            </div>

            <div class="pg-result-explanation">
                ${escapeHtml(message)}
            </div>

        </div>
    `;
}

function escapeHtml(value) {
    const div = document.createElement('div');

    div.textContent = String(value ?? '');

    return div.innerHTML;
}

const submenuToggle = document.querySelector('.pg-submenu-toggle');

if (submenuToggle) {
    submenuToggle.addEventListener('click', function () {
        const parent = this.closest('.pg-nav-parent');
        const submenu = parent.nextElementSibling;

        const isOpen = submenu.classList.toggle('open');

        parent.classList.toggle('open', isOpen);
        this.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });
}