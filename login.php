<?php
session_start();

// Database connection file
require 'db-connect.php';

function validateUser($pdo, $username, $password) {
    $stmt = $pdo->prepare("SELECT * FROM event_user WHERE event_user_name = ? AND event_user_password = ?");
    $stmt->bindParam(1, $username);
    $stmt->bindParam(2, $password);

    $stmt->execute();

    return $stmt->rowCount() > 0;
}

$error = "";
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (validateUser($pdo, $username, $password)) {
        $_SESSION['validUser'] = true;
        header("Location: homepage.php");
        exit();
    } else {
        $error = "Invalid username or password";
    }
}

if (!isset($_SESSION['validUser']) || $_SESSION['validUser'] != true) {
    if ($error != "") {
        echo "<p>$error</p>";
    }
    ?>
    <form action="login.php" method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    <?php
}
?>
