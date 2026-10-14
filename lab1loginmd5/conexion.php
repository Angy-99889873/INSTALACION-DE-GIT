<?php
// ============================================================
// LABORATORIO 1 – LOGIN VULNERABLE CON MD5
// GSR600 – Seguridad Informática
// Archivo: conexion.php
// Conexión segura con PDO a la base de datos MySQL (gsr600)
// ============================================================

$host = 'localhost';
$dbname = 'gsr600';
$username = 'root';
$password = '';
$charset = 'utf8mb4';

$dsn = "mysql:host={$host};dbname={$dbname};charset={$charset}";

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // Consultas preparadas reales para evitar SQL Injection
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . $charset
];

try {
    $pdo = new PDO($dsn, $username, $password, $options);
} catch (PDOException $e) {
    error_log("Error de conexión en Lab 1: " . $e->getMessage());
    die("<div style='font-family:sans-serif;padding:20px;background:#fee2e2;color:#991b1b;border:1px solid #f87171;border-radius:8px;max-width:600px;margin:50px auto;'>"
        . "<h3 style='margin-top:0;'>Error de Conexión a la Base de Datos</h3>"
        . "<p>No fue posible conectar con MySQL. Asegúrese de que XAMPP MySQL esté iniciado y de haber importado <code>database.sql</code>.</p>"
        . "<small>Detalle técnico: " . htmlspecialchars($e->getMessage()) . "</small>"
        . "</div>");
}
