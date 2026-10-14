<?php
// ============================================================
// LABORATORIO 1 – LOGIN VULNERABLE CON MD5
// GSR600 – Seguridad Informática
// Archivo: index.php
// Sistema de Autenticación, Dashboard y Laboratorio Didáctico
// ============================================================

session_start();
require_once 'conexion.php';

$mensaje = '';
$tipo_mensaje = ''; // 'danger', 'success', 'warning'

// 1. Cerrar Sesión
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header("Location: index.php");
    exit;
}

// 2. Procesar Formulario de Inicio de Sesión
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'login') {
    $identificador = trim($_POST['identificador'] ?? '');
    $password_plano = $_POST['password'] ?? '';

    if (empty($identificador) || empty($password_plano)) {
        $tipo_mensaje = 'danger';
        $mensaje = 'Por favor complete todos los campos requeridos.';
    } else {
        // LABORATORIO DIDÁCTICO 1:
        // Se calcula el hash MD5 sin salt intencionalmente
        $hash_md5 = md5($password_plano);

        // Búsqueda por nombre de usuario o por correo electrónico
        $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE (usuario = :id_u OR email = :id_e) LIMIT 1");
        $stmt->execute([
            ':id_u' => $identificador,
            ':id_e' => $identificador
        ]);
        $usuario = $stmt->fetch();

        if ($usuario && $usuario['password'] === $hash_md5) {
            // Verificar estado de la cuenta (1 = Activo, 0 = Inactivo)
            if ((int)$usuario['estado'] !== 1) {
                $tipo_mensaje = 'warning';
                $mensaje = 'Acceso Denegado: La cuenta del usuario "' . htmlspecialchars($usuario['usuario']) . '" se encuentra INACTIVA o suspendida (estado = 0).';
            } else {
                // Registrar último login
                $update = $pdo->prepare("UPDATE usuarios SET ultimo_login = NOW() WHERE id = :id");
                $update->execute([':id' => $usuario['id']]);

                // Guardar en sesión
                $_SESSION['usuario_id'] = $usuario['id'];
                $_SESSION['nombres'] = $usuario['nombres'];
                $_SESSION['apellidos'] = $usuario['apellidos'];
                $_SESSION['usuario'] = $usuario['usuario'];
                $_SESSION['email'] = $usuario['email'];
                $_SESSION['telefono'] = $usuario['telefono'];
                $_SESSION['rol'] = $usuario['rol'];
                $_SESSION['hash_md5'] = $usuario['password'];
                $_SESSION['ultimo_login'] = $usuario['ultimo_login'] ?? date('Y-m-d H:i:s');

                $tipo_mensaje = 'success';
                $mensaje = 'Autenticación exitosa con MD5.';
            }
        } else {
            $tipo_mensaje = 'danger';
            $mensaje = 'Credenciales inválidas: Usuario o contraseña incorrectos.';
        }
    }
}

// Consultar lista completa de usuarios para la auditoría y demostración
$stmt_all = $pdo->query("SELECT id, nombres, apellidos, usuario, email, rol, estado, password, ultimo_login FROM usuarios ORDER BY id ASC");
$todos_usuarios = $stmt_all->fetchAll();

// Diccionario didáctico simulador de Tabla Arcoíris (Rainbow Table)
$rainbow_table = [
    'e10adc3949ba59abbe56e057f20f883e' => '123456',
    '5f4dcc3b5aa765d61d8327deb882cf99' => 'password',
    '0192023a7bbd73250516f069df18b500' => 'admin123',
    '25d55ad283aa400af464c76d713c07ad' => '12345678',
    'd8578edf8458ce06fbc5bb76a58c5ca4' => 'qwerty',
    '9db2c10e0cdad4ab0b87adf2fc69a35b' => 'invitado',
    '827ccb0eea8a706c4c34a16891f84e7b' => '12345',
    'c33367701511b4f6020ec61ded352059' => 'admin',
    '21232f297a57a5a743894a0e4a801fc3' => 'admin',
    '63a9f0ea7bb98050796b649e85481845' => 'root'
];

$lookup_result = null;
$lookup_time = 0;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'rainbow_lookup') {
    $search_hash = strtolower(trim($_POST['search_hash'] ?? ''));
    $t0 = microtime(true);
    if (isset($rainbow_table[$search_hash])) {
        $lookup_result = [
            'encontrado' => true,
            'hash' => $search_hash,
            'password' => $rainbow_table[$search_hash]
        ];
    } else {
        $lookup_result = [
            'encontrado' => false,
            'hash' => $search_hash
        ];
    }
    $lookup_time = round((microtime(true) - $t0) * 1000, 4);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laboratorio 1 - Login Vulnerable con MD5 | GSR600</title>
    <!-- Bootstrap 5.3+ -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --bg-body: #0b0f19;
            --card-bg: #111827;
            --card-border: #1f2937;
            --accent-red: #ef4444;
            --accent-blue: #3b82f6;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
        }

        body {
            background-color: var(--bg-body);
            color: #f1f5f9;
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
            padding: 35px 15px;
        }

        .main-container {
            max-width: 1120px;
            margin: 0 auto;
        }

        .badge-lab {
            background: linear-gradient(135deg, #b91c1c, #dc2626);
            color: #fff;
            font-size: 0.8rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            padding: 6px 14px;
            border-radius: 20px;
            display: inline-block;
            margin-bottom: 10px;
            font-weight: 700;
        }

        .card-custom {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
            overflow: hidden;
            margin-bottom: 24px;
        }

        .card-header-title {
            background: linear-gradient(135deg, #1f2937, #111827);
            border-bottom: 1px solid var(--card-border);
            padding: 20px 24px;
        }

        .form-control {
            background-color: #1f2937;
            border: 1px solid #374151;
            color: #f9fafb;
            padding: 10px 14px;
            border-radius: 8px;
        }

        .form-control:focus {
            background-color: #1f2937;
            border-color: var(--accent-red);
            color: #ffffff;
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.25);
        }

        .btn-md5-login {
            background: linear-gradient(135deg, #dc2626, #b91c1c);
            color: #ffffff;
            font-weight: 600;
            padding: 11px;
            border: none;
            border-radius: 8px;
            width: 100%;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.2s;
        }

        .btn-md5-login:hover {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: #ffffff;
            box-shadow: 0 4px 15px rgba(220, 38, 38, 0.4);
        }

        .code-hash {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #030712;
            color: #f87171;
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            word-break: break-all;
            border: 1px solid #1f2937;
            display: inline-block;
        }

        .user-quick-btn {
            background: #1f2937;
            border: 1px solid #374151;
            color: #93c5fd;
            font-size: 0.75rem;
            padding: 5px 9px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.15s;
        }
        .user-quick-btn:hover {
            background: #2563eb;
            color: #fff;
            border-color: #2563eb;
        }
        .user-quick-btn.inactive {
            color: #fca5a5;
            border-color: #7f1d1d;
        }
        .user-quick-btn.inactive:hover {
            background: #dc2626;
            color: #fff;
        }

        .table-dark-custom {
            --bs-table-bg: #111827;
            --bs-table-border-color: #1f2937;
            font-size: 0.82rem;
        }
    </style>
</head>
<body>

<div class="main-container">

    <!-- Encabezado Principal -->
    <div class="text-center mb-4">
        <span class="badge-lab"><i class="bi bi-shield-exclamation me-1"></i> Laboratorio 1 &bull; GSR600</span>
        <h1 class="fw-bold tracking-tight mb-2">LOGIN VULNERABLE CON MD5</h1>
        <p class="text-secondary mx-auto" style="max-width: 780px;">
            Estudio didáctico de las debilidades de la función <strong>MD5 sin Salt</strong>: colisiones, velocidad excesiva de cómputo, vulnerabilidad ante <strong>Tablas Arcoíris (Rainbow Tables)</strong> y ausencia de salting aleatorio.
        </p>
    </div>

    <!-- Alertas del Sistema -->
    <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?= $tipo_mensaje ?> alert-dismissible fade show d-flex align-items-center mb-4" role="alert">
            <i class="bi bi-<?= $tipo_mensaje === 'success' ? 'check-circle-fill' : ($tipo_mensaje === 'warning' ? 'exclamation-circle-fill' : 'exclamation-triangle-fill') ?> me-2 fs-5"></i>
            <div><?= htmlspecialchars($mensaje) ?></div>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- PANEL DE SESIÓN ACTIVA (Si el usuario ya inició sesión) -->
    <?php if (isset($_SESSION['usuario_id'])): ?>
        <div class="card-custom border-success mb-4">
            <div class="p-4" style="background: linear-gradient(135deg, #064e3b, #0f172a);">
                <div class="d-flex justify-content-between align-items-center flex-wrap gap-3">
                    <div>
                        <span class="badge bg-success mb-2"><i class="bi bi-person-check-fill me-1"></i> Sesión Autenticada</span>
                        <h3 class="fw-bold m-0 text-white">¡Bienvenido(a), <?= htmlspecialchars($_SESSION['nombres'] . ' ' . $_SESSION['apellidos']) ?>!</h3>
                        <div class="text-white-50 small mt-1">
                            Usuario: <code><?= htmlspecialchars($_SESSION['usuario']) ?></code> &bull; 
                            Email: <code><?= htmlspecialchars($_SESSION['email']) ?></code> &bull; 
                            Rol: <span class="badge bg-primary text-uppercase"><?= htmlspecialchars($_SESSION['rol']) ?></span> &bull; 
                            Último acceso: <?= htmlspecialchars($_SESSION['ultimo_login']) ?>
                        </div>
                    </div>
                    <div>
                        <a href="index.php?action=logout" class="btn btn-danger btn-sm px-3 py-2 fw-bold">
                            <i class="bi bi-box-arrow-right me-1"></i> Cerrar Sesión
                        </a>
                    </div>
                </div>

                <div class="mt-3 p-3 rounded-3" style="background: rgba(0, 0, 0, 0.4); border: 1px solid rgba(255, 255, 255, 0.1);">
                    <small class="text-secondary d-block mb-1">Hash MD5 almacenado en BD para esta cuenta (32 caracteres hexadecimales):</small>
                    <code class="text-warning fs-6"><?= htmlspecialchars($_SESSION['hash_md5']) ?></code>
                    <small class="text-danger-emphasis d-block mt-2">
                        <i class="bi bi-exclamation-octagon-fill text-danger me-1"></i>
                        <strong>Observación de Seguridad:</strong> Este hash se calculó directamente con <code>md5($password)</code> sin ningún tipo de salt. Cualquier persona con acceso a la base de datos puede descifrarlo en segundos con una tabla arcoíris.
                    </small>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <div class="row g-4">
        <!-- COLUMNA IZQUIERDA: Formulario de Login -->
        <div class="col-lg-5">
            <div class="card-custom">
                <div class="card-header-title d-flex justify-content-between align-items-center">
                    <div>
                        <h5 class="m-0 fw-bold text-white"><i class="bi bi-key-fill text-danger me-2"></i>Acceso al Sistema</h5>
                        <small class="text-secondary">Autenticación mediante <code>md5($pass)</code></small>
                    </div>
                    <span class="badge bg-danger">Vulnerable</span>
                </div>

                <div class="p-4">
                    <form action="index.php" method="POST" autocomplete="off">
                        <input type="hidden" name="action" value="login">

                        <div class="mb-3">
                            <label for="identificador" class="form-label text-secondary fw-semibold">Usuario o Email</label>
                            <div class="input-group">
                                <span class="input-group-text bg-dark border-secondary text-secondary"><i class="bi bi-person"></i></span>
                                <input type="text" class="form-control" id="identificador" name="identificador" required placeholder="admin o admin@lab.local">
                            </div>
                        </div>

                        <div class="mb-4">
                            <div class="d-flex justify-content-between align-items-center">
                                <label for="password" class="form-label text-secondary fw-semibold mb-0">Contraseña</label>
                                <a href="recuperar.php" class="small text-info text-decoration-none"><i class="bi bi-question-circle"></i> ¿Olvidaste tu contraseña?</a>
                            </div>
                            <div class="input-group mt-1">
                                <span class="input-group-text bg-dark border-secondary text-secondary"><i class="bi bi-lock"></i></span>
                                <input type="password" class="form-control" id="password" name="password" required placeholder="Contraseña de prueba">
                            </div>
                        </div>

                        <button type="submit" class="btn btn-md5-login mb-3">
                            <i class="bi bi-box-arrow-in-right me-1"></i> Iniciar Sesión con MD5
                        </button>
                    </form>

                    <!-- Botones Rápidos de Prueba -->
                    <div class="mt-4 pt-3 border-top border-secondary-subtle">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <small class="text-secondary fw-semibold"><i class="bi bi-lightning-charge-fill text-warning me-1"></i> Credenciales de Prueba del Docente:</small>
                        </div>
                        <div class="d-flex flex-wrap gap-2">
                            <button type="button" class="user-quick-btn" onclick="rellenar('admin', '123456')">admin / 123456</button>
                            <button type="button" class="user-quick-btn" onclick="rellenar('docente', 'password')">docente / password</button>
                            <button type="button" class="user-quick-btn" onclick="rellenar('estudiante1', 'admin123')">estudiante1 / admin123</button>
                            <button type="button" class="user-quick-btn" onclick="rellenar('estudiante2', '123456')">estudiante2 / 123456</button>
                            <button type="button" class="user-quick-btn" onclick="rellenar('estudiante3', '12345678')">estudiante3 / 12345678</button>
                            <button type="button" class="user-quick-btn inactive" onclick="rellenar('estudiante4', 'qwerty')" title="Cuenta inactiva (estado=0)">estudiante4 / qwerty (Inactivo)</button>
                            <button type="button" class="user-quick-btn" onclick="rellenar('invitado', 'invitado')">invitado / invitado</button>
                        </div>
                    </div>

                    <!-- Enlace directo al módulo de tokens -->
                    <div class="mt-4 p-3 rounded-3" style="background:#0f172a; border: 1px solid #1e2937;">
                        <small class="text-secondary d-block mb-1"><i class="bi bi-arrow-repeat text-info me-1"></i> Módulo de Restablecimiento de Claves:</small>
                        <a href="recuperar.php" class="btn btn-sm btn-outline-info w-100">
                            Ir a Recuperar Contraseña (<code>password_resets</code>)
                        </a>
                    </div>

                </div>
            </div>
        </div>

        <!-- COLUMNA DERECHA: Laboratorio Didáctico de MD5 y Simulador de Rainbow Tables -->
        <div class="col-lg-7">

            <!-- 1. Alerta Didáctica: Ausencia de Salt y Mismo Hash -->
            <div class="card-custom border-danger">
                <div class="card-header-title d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="m-0 fw-bold text-danger"><i class="bi bi-exclamation-triangle-fill me-2"></i>Demostración Crítica: Ausencia de Salt</h6>
                        <small class="text-secondary">Comparativa de usuarios con la misma contraseña en el script del docente</small>
                    </div>
                    <span class="badge bg-danger">Vulnerabilidad Crítica</span>
                </div>
                <div class="p-4">
                    <p class="small text-secondary mb-3">
                        En la base de datos creada por el docente, tanto <code>admin</code> como <code>estudiante2</code> utilizan la contraseña <code>123456</code>. Debido a que <strong>MD5 no incorpora una Salt aleatoria</strong>, el valor resultante en la base de datos es <strong>exactamente idéntico</strong>:
                    </p>

                    <div class="table-responsive">
                        <table class="table table-dark table-sm table-bordered align-middle" style="font-size:0.78rem;">
                            <thead>
                                <tr class="text-secondary">
                                    <th>Usuario</th>
                                    <th>Clave en Texto Plano</th>
                                    <th>Hash MD5 en Base de Datos</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><span class="badge bg-danger">admin</span></td>
                                    <td><code>123456</code></td>
                                    <td><span class="code-hash text-warning">e10adc3949ba59abbe56e057f20f883e</span></td>
                                </tr>
                                <tr>
                                    <td><span class="badge bg-primary">estudiante2</span></td>
                                    <td><code>123456</code></td>
                                    <td><span class="code-hash text-warning">e10adc3949ba59abbe56e057f20f883e</span></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="small text-danger" style="font-size:0.77rem;">
                        <strong>Impacto en Seguridad:</strong> Un atacante que observe la base de datos sabe de inmediato que ambos usuarios comparten la misma contraseña, y si logra descifrar a uno (el estudiante), inmediatamente obtiene la clave del Administrador del Sistema.
                    </div>
                </div>
            </div>

            <!-- 2. Simulador de Tablas Arcoíris (Rainbow Table Lookup) -->
            <div class="card-custom">
                <div class="card-header-title d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="m-0 fw-bold text-white"><i class="bi bi-search text-warning me-2"></i>Simulador de Ataque con Tablas Arcoíris</h6>
                        <small class="text-secondary">Búsqueda inversa instantánea en diccionario precalculado de hashes</small>
                    </div>
                    <span class="badge bg-warning text-dark">Pre-computation</span>
                </div>
                <div class="p-4">
                    <form action="index.php" method="POST">
                        <input type="hidden" name="action" value="rainbow_lookup">
                        <div class="mb-3">
                            <label for="search_hash" class="form-label text-secondary small fw-semibold">Ingrese un Hash MD5 para "revertir":</label>
                            <div class="input-group">
                                <input type="text" class="form-control form-control-sm font-monospace" id="search_hash" name="search_hash" required placeholder="Ej. e10adc3949ba59abbe56e057f20f883e" value="<?= htmlspecialchars($_POST['search_hash'] ?? 'e10adc3949ba59abbe56e057f20f883e') ?>">
                                <button type="submit" class="btn btn-warning btn-sm fw-bold">
                                    <i class="bi bi-lightning-charge"></i> Buscar
                                </button>
                            </div>
                        </div>
                    </form>

                    <?php if ($lookup_result !== null): ?>
                        <div class="p-3 rounded-3 mt-2" style="background:#0f172a; border: 1px solid #1f2937;">
                            <?php if ($lookup_result['encontrado']): ?>
                                <div class="text-success fw-bold small mb-1">
                                    <i class="bi bi-check-circle-fill me-1"></i> ¡Hash descifrado en <?= $lookup_time ?> ms!
                                </div>
                                <div class="small text-secondary">
                                    <strong>Contraseña recuperada:</strong> <span class="badge bg-success fs-6 text-white"><?= htmlspecialchars($lookup_result['password']) ?></span>
                                </div>
                                <div class="text-muted mt-1" style="font-size:0.73rem;">
                                    El atacante no realizó fuerza bruta en tiempo real; simplemente consultó una base de datos de pares clave-hash precalculada.
                                </div>
                            <?php else: ?>
                                <div class="text-danger small">
                                    <i class="bi bi-x-circle-fill me-1"></i> Hash no encontrado en la muestra local del diccionario. En una Rainbow Table comercial (ej. CrackStation con billones de hashes), este hash sería encontrado en segundos.
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- 3. Calculadora MD5 en tiempo real con JavaScript -->
            <div class="card-custom">
                <div class="card-header-title">
                    <h6 class="m-0 fw-bold text-white"><i class="bi bi-calculator text-info me-2"></i>Calculadora MD5 en Tiempo Real</h6>
                    <small class="text-secondary">Efecto avalancha y longitud fija (128 bits / 32 caracteres hexadecimales)</small>
                </div>
                <div class="p-4">
                    <div class="mb-3">
                        <label for="live-input" class="form-label text-secondary small fw-semibold">Escribe cualquier texto o contraseña:</label>
                        <input type="text" id="live-input" class="form-control form-control-sm" placeholder="Escribe aquí para calcular el hash..." value="123456" oninput="calcularMD5EnVivo()">
                    </div>
                    <div>
                        <small class="text-secondary d-block mb-1">Hash MD5 resultante:</small>
                        <div id="live-output" class="code-hash w-100" style="font-size:0.85rem; color:#38bdf8;">e10adc3949ba59abbe56e057f20f883e</div>
                        <div class="d-flex justify-content-between text-secondary mt-1" style="font-size:0.72rem;">
                            <span>Longitud: 32 caracteres hex (128 bits)</span>
                            <span>Algoritmo: MD5 (RFC 1321)</span>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <!-- TABLA DE AUDITORÍA: Usuarios registrados en la Base de Datos -->
    <div class="card-custom mt-2">
        <div class="card-header-title d-flex justify-content-between align-items-center">
            <div>
                <h5 class="m-0 fw-bold text-white"><i class="bi bi-database text-primary me-2"></i>Auditoría de Usuarios en Base de Datos (<code>gsr600.usuarios</code>)</h5>
                <small class="text-secondary">Datos iniciales creados por el script del Licenciado</small>
            </div>
            <span class="badge bg-secondary"><?= count($todos_usuarios) ?> Registros</span>
        </div>
        <div class="p-4">
            <div class="table-responsive">
                <table class="table table-dark table-striped table-bordered table-dark-custom align-middle">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Nombres y Apellidos</th>
                            <th>Usuario</th>
                            <th>Email</th>
                            <th>Rol</th>
                            <th>Estado</th>
                            <th>Hash MD5 Almacenado</th>
                            <th>Último Login</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($todos_usuarios as $u): ?>
                            <tr>
                                <td><?= htmlspecialchars((string)$u['id']) ?></td>
                                <td><?= htmlspecialchars($u['nombres'] . ' ' . $u['apellidos']) ?></td>
                                <td><span class="badge bg-secondary"><?= htmlspecialchars($u['usuario']) ?></span></td>
                                <td><small class="text-muted"><?= htmlspecialchars($u['email']) ?></small></td>
                                <td><span class="badge bg-info text-dark text-uppercase"><?= htmlspecialchars($u['rol']) ?></span></td>
                                <td>
                                    <?php if ((int)$u['estado'] === 1): ?>
                                        <span class="badge bg-success">Activo (1)</span>
                                    <?php else: ?>
                                        <span class="badge bg-danger">Inactivo (0)</span>
                                    <?php endif; ?>
                                </td>
                                <td><code style="font-size:0.73rem; color:#f87171;"><?= htmlspecialchars($u['password']) ?></code></td>
                                <td><small class="text-secondary"><?= htmlspecialchars($u['ultimo_login'] ?? 'Nunca') ?></small></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

</div>

<!-- Biblioteca ligera de MD5 en JavaScript para cálculo en tiempo real -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/blueimp-md5/2.19.0/js/md5.min.js"></script>
<script>
function rellenar(u, p) {
    document.getElementById('identificador').value = u;
    document.getElementById('password').value = p;
}

function calcularMD5EnVivo() {
    const input = document.getElementById('live-input').value;
    const hash = md5(input);
    document.getElementById('live-output').textContent = hash;
}
</script>

<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
