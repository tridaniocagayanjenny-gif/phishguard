<header class="pg-topbar">

    <div class="pg-topbar-left">

        <button
            class="pg-mobile-menu"
            type="button"
            id="pgMobileMenu"
        >
            <i class="fa-solid fa-bars"></i>
        </button>

        <div>

            <h1 class="pg-page-title">
                <?= htmlspecialchars($pageTitle ?? 'Dashboard') ?>
            </h1>

            <?php if (!empty($pageSubtitle)): ?>

                <div class="pg-page-subtitle">
                    <?= htmlspecialchars($pageSubtitle) ?>
                </div>

            <?php endif; ?>

        </div>

    </div>

    <div class="pg-top-user">

        <div class="pg-user-info">

            <strong>
                <?= htmlspecialchars($userName ?? 'Administrator') ?>
            </strong>

            <span>Administrator</span>

        </div>

        <div class="pg-avatar">
            <?= htmlspecialchars($userInitial ?? 'A') ?>
        </div>

    </div>

</header>