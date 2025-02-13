<?php
require 'includes/db.php';
require 'includes/rsa.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $encryptedPassword = $_POST['password'];

    // Dekripsi password
    $keys = generateRSAKeys();
    $decryptedPassword = decryptRSA($encryptedPassword, $keys['private']);

    // Hash password
    $hashedPassword = password_hash($decryptedPassword, PASSWORD_BCRYPT);

    // Simpan user ke database
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$username, $hashedPassword]);

    echo "Registrasi berhasil! <a href='index.php'>Login disini</a>";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.2.1/jsencrypt.min.js"></script>
    <script>
        function submitForm() {
            const publicKey = `<?php echo $keys['public']; ?>`;
            const password = document.getElementById('password').value;
            const encryptedPassword = encryptPassword(password, publicKey);

            document.getElementById('encryptedPassword').value = encryptedPassword;
            document.getElementById('registerForm').submit();
        }
    </script>
</head>
<body>
    <h1>Register</h1>
    <form id="registerForm" method="POST" onsubmit="event.preventDefault(); submitForm();">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <input type="hidden" id="encryptedPassword" name="password">
        <button type="submit">Register</button>
    </form>
</body>
</html>