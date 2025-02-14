<?php
session_start();
require 'includes/db.php';
require 'includes/rsa.php';

// Generate RSA keys
$keys = generateRSAKeys();
$_SESSION['private_key'] = $keys['private']; // Simpan private key di session

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $encryptedPassword = $_POST['password'];

    // Dekripsi password
    $decryptedPassword = decryptRSA($encryptedPassword, $_SESSION['private_key']);

    // Cek user di database
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($decryptedPassword, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        header('Location: dashboard.php');
        exit();
    } else {
        echo "Login gagal!";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.2.1/jsencrypt.min.js"></script>
    <script>
        function submitForm() {
            const publicKey = `<?php echo $keys['public']; ?>`;
            const password = document.getElementById('password').value;
            const encryptedPassword = encryptPassword(password, publicKey);

            document.getElementById('encryptedPassword').value = encryptedPassword;
            document.getElementById('loginForm').submit();
        }
    </script>
</head>
<body>
    <h1>Login</h1>
    <form id="loginForm" method="POST" onsubmit="event.preventDefault(); submitForm();">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <input type="hidden" id="encryptedPassword" name="password">
        <button type="submit">Login</button>
    </form>

    <!-- Tombol Login dengan Google -->
    <a href="http://localhost:5000/auth/google">
        <button style="background-color: white; border: 1px solid #ccc; padding: 10px; cursor: pointer;">
            <img src="https://developers.google.com/identity/images/g-logo.png" alt="Google Logo" width="20">
            Login dengan Google
        </button>
    </a>

    <p>Belum punya akun? <a href="register.php">Daftar disini</a></p>
</body>
</html>
