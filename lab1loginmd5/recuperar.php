<?php
// ============================================================
// LABORATORIO 1 – RECUPERACIÓN DE CONTRASEÑAS (PASSWORD RESETS)
// GSR600 – Seguridad Informática
// Archivo: recuperar.php
// Implementación didáctica con la tabla `password_resets`
// ============================================================

require_once 'conexion.php';

$mensaje = '';
$tipo_mensaje = '';
$token_generado = null;
$token_valido = false;
$reset_record = null;

// PASO 2: Procesar restablecimiento mediante token activo
$token_param = trim($_GET['token'] ?? '');

if (!empty($token_param)) {
    $stmt_check = $pdo->prepare("SELECT * FROM password_resets WHERE token = :token AND used = 0 AND expires_at > NOW() LIMIT 1");
    $stmt_check->execute([':token' => $token_param]);
    $reset_record = $stmt_check->fetch();

    if ($reset_record) {
        $token_valido = true;
    } else {
        $tipo_mensaje = 'danger';
        $mensaje = 'El token de recuperación es inválido, ya fue utilizado o ha expirado.';
    }
}

// Acción: Cambiar la contraseña con el token
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'reset_password') {
    $token_post = trim($_POST['token'] ?? '');
    $nueva_pass = $_POST['nueva_password'] ?? '';
    $conf_pass = $_POST['confirmar_password'] ?? '';

    if (empty($nueva_pass) || empty($conf_pass)) {
        $tipo_mensaje = 'danger';
        $mensaje = 'Por favor complete la nueva contraseña y su confirmación.';
    } elseif ($nueva_pass !== $conf_pass) {
        $tipo_mensaje = 'danger';
        $mensaje = 'Las contraseñas no coinciden.';
    } else {
        // Verificar token nuevamente
        $stmt_v = $pdo->prepare("SELECT * FROM password_resets WHERE token = :token AND used = 0 AND expires_at > NOW() LIMIT 1");
        $stmt_v->execute([':token' => $token_post]);
        $r = $stmt_v->fetch();

        if ($r) {
            // Actualizar contraseña en tabla usuarios con md5()
            $nuevo_hash = md5($nueva_pass);
            $stmt_u = $pdo->prepare("UPDATE usuarios SET password = :hash WHERE email = :email");
            $stmt_u->execute([
                ':hash' => $nuevo_hash,
                ':email' => $r['email']
            ]);

            // Marcar token como utilizado
            $stmt_m = $pdo->prepare("UPDATE password_resets SET used = 1 WHERE id = :id");
            $stmt_m->execute([':id' => $r['id']]);

            $tipo_mensaje = 'success';
            $mensaje = '¡Contraseña actualizada con éxito mediante MD5! Ya puede iniciar sesión con su nueva clave.';
            $token_valido = false;
        } else {
            $tipo_mensaje = 'danger';
            $mensaje = 'El token ya no es válido o ha expirado.';
        }
    }
}

// PASO 1: Procesar solicitud de nuevo token
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'request_token') {
    $email = trim($_POST['email'] ?? '');

    if (empty($email)) {
        $tipo_mensaje = 'danger';
        $mensaje = 'Por favor ingrese su correo electrónico.';
    } else {
        // Verificar si el correo existe en usuarios
        $stmt_u = $pdo->prepare("SELECT id, nombres, usuario FROM usuarios WHERE email = :email LIMIT 1");
        $stmt_u->execute([':email' => $email]);
        $user = $stmt_u->fetch();

        if ($user) {
            // Generar token seguro de 64 caracteres hexadecimales (256 bits)
            $token = bin2hex(random_bytes(32));
            // Expiración en 1 hora
            $stmt_t = $pdo->prepare("INSERT INTO password_resets (email, token, expires_at, used) VALUES (:email, :token, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)");
            $stmt_t->execute([
                ':email' => $email,
                ':token' => $token
            ]);

            $token_generado = $token;
            $tipo_mensaje = 'success';
            $mensaje = 'Token de recuperación generado exitosamente para ' . htmlspecialchars($email);
        } else {
            // Por seguridad se recomienda mensaje ambiguo, pero para fines didácticos indicamos el resultado
            $tipo_mensaje = 'warning';
            $mensaje = 'No existe ningún usuario registrado con el correo: ' . htmlspecialchars($email);
        }
    }
}

// Consultar tokens recientes para auditoría didáctica
$stmt_tokens = $pdo->query("SELECT id, email, LEFT(token, 20) AS token_short, token, expires_at, used, created_at FROM password_resets ORDER BY id DESC LIMIT 5");
$historial_tokens = $stmt_tokens->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recuperación de Contraseña - Laboratorio 1 | GSR600</title>
    <!-- Bootstrap 5.3+ -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        body {
            background-color: #0b0f19;
            color: #f1f5f9;
            min-height: 100vh;
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            padding: 40px 15px;
        }
        .main-card {
            max-width: 850px;
            margin: 0 auto;
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
            overflow: hidden;
        }
        .card-header-title {
            background: linear-gradient(135deg, #1e3a8a, #0f172a);
            padding: 22px 28px;
            border-bottom: 1px solid #1f2937;
        }
        .form-control {
            background-color: #1f2937;
            border: 1px solid #374151;
            color: #f9fafb;
            padding: 10px 14px;
        }
        .form-control:focus {
            background-color: #1f2937;
            border-color: #3b82f6;
            color: #fff;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25);
        }
    </style>
</head>
<body>

<div class="main-card">
    <div class="card-header-title d-flex justify-content-between align-items-center">
        <div>
            <span class="badge bg-primary mb-1">GSR600 &bull; Laboratorio 1</span>
            <h4 class="fw-bold text-white m-0"><i class="bi bi-shield-lock text-info me-2"></i>Recuperación de Contraseña</h4>
            <small class="text-white-50">Módulo didáctico vinculado a la tabla <code>password_resets</code></small>
        </div>
        <div>
            <a href="index.php" class="btn btn-outline-light btn-sm"><i class="bi bi-arrow-left me-1"></i> Volver al Login</a>
        </div>
    </div>

    <div class="p-4">
        <!-- Alertas -->
        <?php if (!empty($mensaje)): ?>
            <div class="alert alert-<?= $tipo_mensaje ?> alert-dismissible fade show" role="alert">
                <?= htmlspecialchars($mensaje) ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        <?php endif; ?>

        <?php if ($token_valido && $reset_record): ?>
            <!-- FORMULARIO 2: Ingreso de nueva contraseña tras validar token -->
            <div class="p-4 rounded-3 mb-4" style="background:#0f172a; border: 1px solid #1e2937;">
                <h5 class="fw-bold text-success mb-3"><i class="bi bi-check-circle-fill me-2"></i>Token Válido Confirmado</h5>
                <p class="small text-secondary mb-3">
                    Restableciendo la clave para la cuenta: <strong><?= htmlspecialchars($reset_record['email']) ?></strong>
                </p>

                <form action="recuperar.php" method="POST">
                    <input type="hidden" name="action" value="reset_password">
                    <input type="hidden" name="token" value="<?= htmlspecialchars($token_param) ?>">

                    <div class="mb-3">
                        <label for="nueva_password" class="form-label text-secondary small fw-semibold">Nueva Contraseña</label>
                        <input type="password" class="form-control" id="nueva_password" name="nueva_password" required placeholder="Ingrese nueva contraseña">
                    </div>

                    <div class="mb-4">
                        <label for="confirmar_password" class="form-label text-secondary small fw-semibold">Confirmar Nueva Contraseña</label>
                        <input type="password" class="form-control" id="confirmar_password" name="confirmar_password" required placeholder="Repita la nueva contraseña">
                    </div>

                    <button type="submit" class="btn btn-success fw-bold px-4 py-2">
                        <i class="bi bi-arrow-clockwise me-1"></i> Actualizar Contraseña en Base de Datos (MD5)
                    </button>
                </form>
            </div>

        <?php else: ?>

            <!-- FORMULARIO 1: Solicitud de Token -->
            <div class="row g-4 mb-4">
                <div class="col-md-7">
                    <h5 class="fw-bold text-white mb-2">Solicitar Enlace de Recuperación</h5>
                    <p class="small text-secondary mb-3">
                        Ingrese el correo electrónico registrado en la tabla <code>usuarios</code> para emitir un token en <code>password_resets</code>.
                    </p>

                    <form action="recuperar.php" method="POST">
                        <input type="hidden" name="action" value="request_token">
                        <div class="mb-3">
                            <label for="email" class="form-label text-secondary small fw-semibold">Correo Electrónico Registrado</label>
                            <input type="email" class="form-control" id="email" name="email" required placeholder="Ej. admin@lab.local">
                        </div>
                        <button type="submit" class="btn btn-primary fw-bold">
                            <i class="bi bi-send me-1"></i> Generar Token de Recuperación
                        </button>
                    </form>

                    <!-- Sugerencias rápidas -->
                    <div class="mt-3">
                        <small class="text-secondary d-block mb-1">Correos de prueba disponibles:</small>
                        <div class="d-flex flex-wrap gap-2">
                            <button type="button" class="btn btn-sm btn-outline-secondary py-0" onclick="document.getElementById('email').value='admin@lab.local'">admin@lab.local</button>
                            <button type="button" class="btn btn-sm btn-outline-secondary py-0" onclick="document.getElementById('email').value='docente@lab.local'">docente@lab.local</button>
                            <button type="button" class="btn btn-sm btn-outline-secondary py-0" onclick="document.getElementById('email').value='estudiante1@lab.local'">estudiante1@lab.local</button>
                        </div>
                    </div>
                </div>

                <div class="col-md-5">
                    <div class="p-3 rounded-3 h-100" style="background:#0f172a; border: 1px solid #1e2937;">
                        <h6 class="fw-bold text-info mb-2"><i class="bi bi-info-circle me-1"></i> ¿Cómo funciona el token?</h6>
                        <ul class="text-secondary small ps-3 mb-0" style="font-size:0.77rem;">
                            <li class="mb-2">Se genera un token criptográfico pseudoaleatorio de 64 caracteres con <code>bin2hex(random_bytes(32))</code>.</li>
                            <li class="mb-2">Se guarda en la tabla <code>password_resets</code> con tiempo de expiración (1 hora).</li>
                            <li class="mb-2">Al ser consumido, el campo <code>used</code> pasa de 0 a 1 para evitar ataques de repetición (Replay Attacks).</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- SIMULACIÓN DE ENLACE GENERADO -->
            <?php if (!empty($token_generado)): ?>
                <div class="p-3 rounded-3 mb-4" style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3);">
                    <div class="text-success fw-bold small mb-1">
                        <i class="bi bi-envelope-check-fill me-1"></i> [Simulación de Correo] Enlace de recuperación generado:
                    </div>
                    <div class="small text-secondary mb-2">
                        En un entorno de producción, este enlace se enviaría por correo SMTP al usuario:
                    </div>
                    <a href="recuperar.php?token=<?= htmlspecialchars($token_generado) ?>" class="btn btn-sm btn-success fw-bold">
                        <i class="bi bi-box-arrow-up-right me-1"></i> Probar enlace de recuperación: recuperar.php?token=<?= substr($token_generado, 0, 16) ?>...
                    </a>
                </div>
            <?php endif; ?>

        <?php endif; ?>

        <!-- TABLA DE AUDITORÍA DE TOKENS -->
        <div class="mt-4 pt-3 border-top border-secondary-subtle">
            <h6 class="fw-bold text-white mb-2"><i class="bi bi-table text-warning me-2"></i>Registros Recientes en la Tabla <code>password_resets</code></h6>
            <div class="table-responsive">
                <table class="table table-dark table-sm table-bordered align-middle" style="font-size:0.78rem;">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Email</th>
                            <th>Token</th>
                            <th>Expira en</th>
                            <th>Estado</th>
                            <th>Acción Didáctica</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($historial_tokens)): ?>
                            <tr>
                                <td colspan="6" class="text-center text-muted py-2">No hay tokens emitidos todavía. Genera uno con el formulario superior.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($historial_tokens as $t): ?>
                                <tr>
                                    <td><?= htmlspecialchars((string)$t['id']) ?></td>
                                    <td><?= htmlspecialchars($t['email']) ?></td>
                                    <td><code style="font-size:0.72rem; color:#38bdf8;"><?= htmlspecialchars($t['token_short']) ?>...</code></td>
                                    <td><?= htmlspecialchars($t['expires_at']) ?></td>
                                    <td>
                                        <?php if ((int)$t['used'] === 1): ?>
                                            <span class="badge bg-secondary">Usado (1)</span>
                                        <?php else: ?>
                                            <span class="badge bg-success">Activo (0)</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ((int)$t['used'] === 0): ?>
                                            <a href="recuperar.php?token=<?= htmlspecialchars($t['token']) ?>" class="btn btn-xs btn-outline-info py-0 px-2" style="font-size:0.72rem;">Usar Token</a>
                                        <?php else: ?>
                                            <span class="text-muted" style="font-size:0.72rem;">Consumido</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
