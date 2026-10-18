<?php
session_start();

if (isset($_SESSION['user_id'])) {
    header("Location: home.php");
    exit;
}

$error = $_SESSION['register_error'] ?? '';
unset($_SESSION['register_error']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Create Account | PhishGuard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
<?php readfile(__DIR__ . '/../assets/css/style.css'); ?>
</style>
</head>

<body class="auth-page">

<div class="auth-container">

    <div class="auth-brand">
        <div class="brand-logo">PHISHGUARD</div>
        <p>AI-Powered Phishing Detection System</p>
    </div>

    <div class="auth-card">

        <h2>Create Account</h2>
        <p class="text-muted">Create your PhishGuard account.</p>

        <?php if ($error): ?>
            <div class="alert alert-danger">
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <form action="../api/register.php" method="POST">

            <div class="mb-3">
                <label class="form-label">Full Name</label>
                <input
                    type="text"
                    name="full_name"
                    class="form-control"
                    placeholder="Enter your full name"
                    required
                >
            </div>

            <div class="mb-3">
                <label class="form-label">Email Address</label>
                <input
                    type="email"
                    name="email"
                    class="form-control"
                    placeholder="Enter your email"
                    required
                >
            </div>

            <div class="mb-3">
                <label class="form-label">Password</label>
                <input
                    type="password"
                    name="password"
                    class="form-control"
                    placeholder="Create a password"
                    minlength="8"
                    required
                >
            </div>

            <div class="mb-3">
                <label class="form-label">Confirm Password</label>
                <input
                    type="password"
                    name="confirm_password"
                    class="form-control"
                    placeholder="Confirm your password"
                    minlength="8"
                    required
                >
            </div>

            <button type="submit" class="btn btn-primary w-100">
                Create Account
            </button>

        </form>

        <div class="text-center mt-3">
            Already have an account?
            <a href="login.php">Login</a>
        </div>

    </div>

</div>

</body>
</html>