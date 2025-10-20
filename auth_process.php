<?php
session_start();
require_once 'config.php';
if (isset($_POST['register_btn'])) {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['alerts'][] = [
            'type' => 'error',
            'message' => 'Please enter a valid email address.'
        ];
        $_SESSION['active_form'] = 'register';
        header('Location: index.php');
        exit();
    }

    if (strlen($password) < 8 || 
        !preg_match('/[0-9]/', $password) || 
        !preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {

        $_SESSION['alerts'][] = [
            'type' => 'error',
            'message' => 'Password must be at least 8 characters long, include at least one number and one special character.'
        ];
        $_SESSION['active_form'] = 'register';
        header('Location: index.php');
        exit();
    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $check_email = $stmt->get_result();

    if ($check_email->num_rows > 0) {
        $_SESSION['alerts'][] = [
            'type' => 'error',
            'message' => 'Email is already registered!'
        ];
        $_SESSION['active_form'] = 'register';
    } else {
        $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $hashed_password);
        $stmt->execute();

        $_SESSION['alerts'][] = [
            'type' => 'success',
            'message' => 'Registration successful! You can now login.'
        ];
        $_SESSION['active_form'] = 'login';
    }

    header('Location: index.php');
    exit();
}


if (isset($_POST['login_btn'])) {
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);


    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['alerts'][] = [
            'type' => 'error',
            'message' => 'Please enter a valid email address.'
        ];
        $_SESSION['active_form'] = 'login';
        header('Location: index.php');
        exit();
    }

  
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    $user = $result->num_rows > 0 ? $result->fetch_assoc() : null;

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['name'] = $user['name'];
        $_SESSION['alerts'][] = [
            'type' => 'success',
            'message' => 'Login successful'
        ];
    } else {
        $_SESSION['alerts'][] = [
            'type' => 'error',
            'message' => 'Incorrect email or password!'
        ];
        $_SESSION['active_form'] = 'login';
    }

    header('Location: index.php');
    exit();
}
?>
