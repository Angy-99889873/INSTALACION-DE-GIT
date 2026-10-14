<?php
// ============================================================
// LABORATORIO 2 – DEFENSA CONTRA FUERZA BRUTA Y DICCIONARIO
// GSR600 – Seguridad Informática
// Archivo: fuerza_bruta.php
// Implementación de las defensas exigidas en el informe del docente:
// - Límite de intentos (Lockout)
// - Retraso temporal (Rate Limiting)
// - Auditoría de accesos
// ============================================================

session_start();
require_once 'conexion.php';

$mensaje = '';
$tipo_mensaje = '';

// Reiniciar intentos para pruebas pedagógicas
if (isset($_GET['action']) && $_GET['action'] === 'reset') {
    $pdo->query("UPDATE users SET failed_login = 0");
    $_SESSION['intentos_locales'] = 0;
    $_SESSION['bloqueado_hasta'] = 0;
    header("Location: fuerza_bruta.php");
    exit;
}

$intentos_locales = $_SESSION['intentos_locales'] ?? 0;
$bloqueado_hasta = $_SESSION['bloqueado_hasta'] ?? 0;
$tiempo_restante = $bloqueado_hasta - time();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login_bf') {
    $usuario_post = trim($_POST['usuario'] ?? '');
    $pass_post = $_POST['password'] ?? '';

    // 1. Verificar si el sistema está bloqueado por Rate Limiting
    if ($tiempo_restante > 0) {
        $tipo_mensaje = 'danger';
        $mensaje = "SISTEMA BLOQUEADO: Ha superado el número máximo de intentos permitidos. Espere {$tiempo_restante} segundos para volver a intentar (Defensa anti fuerza bruta activa).";
    } else {
        // Consultar usuario en BD
        $stmt = $pdo->prepare("SELECT user_id, user, password, first_name, last_name, failed_login FROM users WHERE user = :u LIMIT 1");
        $stmt->execute([':u' => $usuario_post]);
        $u = $stmt->fetch();

        // En la guía, las claves en BD son MD5
        $hash_ingresado = md5($pass_post);

        if ($u && $u['password'] === $hash_ingresado) {
            // Login correcto: resetear contador
            $pdo->prepare("UPDATE users SET failed_login = 0, last_login = NOW() WHERE user_id = :id")->execute([':id' => $u['user_id']]);
            $_SESSION['intentos_locales'] = 0;
            $_SESSION['bloqueado_hasta'] = 0;
            $tipo_mensaje = 'success';
            $mensaje = "¡Autenticación exitosa! Bienvenido, {$u['first_name']} {$u['last_name']}.";
        } else {
            // Fallo de autenticación
            $_SESSION['intentos_locales'] = ($intentos_locales + 1);
            $intentos_actuales = $_SESSION['intentos_locales'];

            if ($u) {
                $pdo->prepare("UPDATE users SET failed_login = failed_login + 1 WHERE user_id = :id")->execute([':id' => $u['user_id']]);
            }

            if ($intentos_actuales >= 3) {
                // Bloqueo por 60 segundos tras 3 intentos
                $_SESSION['bloqueado_hasta'] = time() + 60;
                $tiempo_restante = 60;
                $tipo_mensaje = 'danger';
                $mensaje = "ALERTA DE SEGURIDAD: 3 intentos fallidos consecutivos detectados. La cuenta ha sido bloqueada temporalmente por 60 segundos para mitigar ataques de diccionario.";
            } else {
                $restantes = 3 - $intentos_actuales;
                $tipo_mensaje = 'warning';
                $mensaje = "Credenciales incorrectas. Intentos fallidos: {$intentos_actuales}/3. Le quedan {$restantes} intento(s) antes del bloqueo temporal.";
            }
        }
    }
}

// Consultar estado de usuarios en la tabla users
$stmt_audit = $pdo->query("SELECT user_id, user, first_name, last_name, failed_login, last_login FROM users");
$usuarios_audit = $stmt_audit->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Defensa contra Fuerza Bruta | Laboratorio 2</title>
    <!-- Bootstrap 5.3+ -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        body {
            background-color: #0b0f19;
            color: #f1f5f9;
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
            padding: 30px 15px;
        }

        .main-container {
            max-width: 1050px;
            margin: 0 auto;
        }

        .card-custom {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
            overflow: hidden;
            margin-bottom: 24px;
        }

        .form-control {
            background-color: #1f2937;
            border: 1px solid #374151;
            color: #f9fafb;
            padding: 10px 14px;
        }
    </style>
</head>
<body>

<div class="main-container">

    <!-- Navegación Superior -->
    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
            <span class="badge bg-info text-dark mb-1"><i class="bi bi-shield-lock me-1"></i> Laboratorio 2 &bull; GSR600</span>
            <h2 class="fw-bold m-0 text-white">DEFENSA CONTRA FUERZA BRUTA Y DICCIONARIO</h2>
            <small class="text-secondary">Implementación de las contramedidas citadas en la sección teórica de la guía</small>
        </div>
        <div class="d-flex gap-2">
            <a href="index.php" class="btn btn-outline-secondary btn-sm"><i class="bi bi-house me-1"></i> Inicio</a>
            <a href="sqli.php" class="btn btn-outline-danger btn-sm"><i class="bi bi-terminal me-1"></i> Inyección SQL</a>
            <a href="xss.php" class="btn btn-outline-warning btn-sm"><i class="bi bi-code-slash me-1"></i> Práctica XSS</a>
        </div>
    </div>

    <!-- Alertas -->
    <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?= $tipo_mensaje ?> d-flex align-items-center mb-4" role="alert">
            <i class="bi bi-<?= $tipo_mensaje === 'success' ? 'check-circle-fill' : 'exclamation-triangle-fill' ?> me-2 fs-5"></i>
            <div><?= htmlspecialchars($mensaje) ?></div>
        </div>
    <?php endif; ?>

    <div class="row g-4">
        <!-- FORMULARIO DE LOGIN PROTEGIDO -->
        <div class="col-lg-6">
            <div class="card-custom">
                <div class="p-3 border-bottom border-secondary-subtle" style="background: linear-gradient(135deg, #1e293b, #0f172a);">
                    <h5 class="m-0 fw-bold text-white"><i class="bi bi-shield-check text-info me-2"></i>Login con Bloqueo por Intentos</h5>
                    <small class="text-secondary">Máximo 3 intentos fallidos permitidos antes del bloqueo temporal</small>
                </div>
                <div class="p-4">
                    <form action="fuerza_bruta.php" method="POST">
                        <input type="hidden" name="action" value="login_bf">

                        <div class="mb-3">
                            <label for="usuario" class="form-label text-secondary small fw-semibold">Usuario:</label>
                            <input type="text" class="form-control" id="usuario" name="usuario" required placeholder="admin, pablo, smithy..." <?= $tiempo_restante > 0 ? 'disabled' : '' ?>>
                        </div>

                        <div class="mb-4">
                            <label for="password" class="form-label text-secondary small fw-semibold">Contraseña:</label>
                            <input type="password" class="form-control" id="password" name="password" required placeholder="Contraseña..." <?= $tiempo_restante > 0 ? 'disabled' : '' ?>>
                        </div>

                        <div class="d-flex gap-2">
                            <button type="submit" class="btn btn-primary fw-bold w-100" <?= $tiempo_restante > 0 ? 'disabled' : '' ?>>
                                <i class="bi bi-box-arrow-in-right me-1"></i> Probar Inicio de Sesión
                            </button>
                            <a href="fuerza_bruta.php?action=reset" class="btn btn-outline-secondary btn-sm text-nowrap" title="Restablecer intentos">
                                <i class="bi bi-arrow-clockwise"></i> Reiniciar
                            </a>
                        </div>
                    </form>

                    <!-- Estado Actual de Intentos -->
                    <div class="mt-4 p-3 rounded-3" style="background:#0f172a; border:1px solid #1f2937;">
                        <div class="d-flex justify-content-between align-items-center small">
                            <span class="text-secondary">Intentos fallidos registrados:</span>
                            <span class="badge <?= ($_SESSION['intentos_locales'] ?? 0) >= 3 ? 'bg-danger' : 'bg-warning text-dark' ?>">
                                <?= $_SESSION['intentos_locales'] ?? 0 ?> / 3
                            </span>
                        </div>
                        <?php if ($tiempo_restante > 0): ?>
                            <div class="text-danger small mt-2 fw-bold">
                                <i class="bi bi-clock-history me-1"></i> Bloqueo activo. Tiempo de espera: <?= $tiempo_restante ?> s
                            </div>
                        <?php endif; ?>
                    </div>

                </div>
            </div>
        </div>

        <!-- CONTRAMEDIDAS EXIGIDAS EN LA GUÍA -->
        <div class="col-lg-6">
            <div class="card-custom p-4">
                <h5 class="fw-bold text-white mb-3"><i class="bi bi-shield-shaded text-success me-2"></i>Contramedidas Exigidas en la Guía</h5>
                <ul class="text-secondary small mb-0 ps-3">
                    <li class="mb-2"><strong>Número de Intentos Permitidos:</strong> Bloquear la cuenta o la IP si se superan 3 a 5 intentos fallidos consecutivos.</li>
                    <li class="mb-2"><strong>Bloqueo Temporal (Rate Limiting):</strong> Aplicar un retraso incremental (ej. 60s, 5m, 15m) que neutraliza la velocidad de los scripts automatizados como Hydra o Burp Suite.</li>
                    <li class="mb-2"><strong>Autenticación Multifactor (MFA/2FA):</strong> Incluso si el atacante adivina la contraseña mediante diccionario, no podrá acceder sin el código temporal del dispositivo móvil.</li>
                    <li class="mb-2"><strong>Uso de WAF (Web Application Firewall):</strong> Detecta anomalías de tráfico y bloquea automáticamente la IP de origen del atacante.</li>
                    <li class="mb-2"><strong>Políticas de Contraseñas Fuertes:</strong> Exigir longitud mínima de 12 caracteres, mayúsculas, números y símbolos para que las claves no existan en diccionarios conocidos.</li>
                </ul>
            </div>

            <!-- Tabla de Auditoría de Intentos en BD -->
            <div class="card-custom p-3">
                <h6 class="fw-bold text-white mb-2" style="font-size:0.85rem;"><i class="bi bi-table text-info me-1"></i> Auditoría de Intentos en BD (Tabla <code>users</code>)</h6>
                <div class="table-responsive">
                    <table class="table table-dark table-sm table-bordered align-middle mb-0" style="font-size:0.75rem;">
                        <thead>
                            <tr><th>Usuario</th><th>Intentos Fallidos</th><th>Último Login</th></tr>
                        </thead>
                        <tbody>
                            <?php foreach ($usuarios_audit as $u): ?>
                                <tr>
                                    <td><?= htmlspecialchars($u['user']) ?></td>
                                    <td><span class="badge <?= $u['failed_login'] > 0 ? 'bg-danger' : 'bg-success' ?>"><?= $u['failed_login'] ?></span></td>
                                    <td><small class="text-muted"><?= htmlspecialchars($u['last_login'] ?? 'Nunca') ?></small></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

</div>

</body>
</html>
