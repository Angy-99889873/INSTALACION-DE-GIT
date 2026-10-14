<?php
// ============================================================
// LABORATORIO 2 – INYECCIÓN SQL (SQLi), XSS Y DEFENSAS WEB
// GSR600 – Seguridad Informática
// Archivo: index.php
// Portal Principal del Laboratorio
// ============================================================

require_once 'conexion.php';

// Obtener usuarios para el panel de información
$stmt = $pdo->query("SELECT user_id, first_name, last_name, user, password FROM users ORDER BY user_id ASC");
$usuarios = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laboratorio 2 - Inyección SQL, XSS y Defensas | GSR600</title>
    <!-- Bootstrap 5.3+ -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        :root {
            --bg-main: #0b0f19;
            --card-bg: #111827;
            --card-border: #1f2937;
        }

        body {
            background-color: var(--bg-main);
            color: #f1f5f9;
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
            padding: 40px 15px;
        }

        .main-container {
            max-width: 1150px;
            margin: 0 auto;
        }

        .badge-lab {
            background: linear-gradient(135deg, #b91c1c, #dc2626);
            color: #fff;
            font-size: 0.82rem;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            padding: 6px 16px;
            border-radius: 20px;
            display: inline-block;
            margin-bottom: 12px;
            font-weight: 700;
        }

        .card-menu {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 14px;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
            transition: all 0.25s ease;
            height: 100%;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .card-menu:hover {
            transform: translateY(-4px);
            border-color: #3b82f6;
            box-shadow: 0 20px 35px rgba(59, 130, 246, 0.2);
        }

        .card-menu-header {
            padding: 24px;
            border-bottom: 1px solid var(--card-border);
        }

        .card-menu-body {
            padding: 24px;
            flex-grow: 1;
        }

        .card-menu-footer {
            padding: 20px 24px;
            border-top: 1px solid var(--card-border);
            background: rgba(0, 0, 0, 0.2);
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
    <div class="text-center mb-5">
        <span class="badge-lab"><i class="bi bi-shield-shaded me-1"></i> Laboratorio 2 &bull; GSR600</span>
        <h1 class="fw-bold tracking-tight mb-2">VULNERABILIDADES WEB: INYECCIÓN SQL Y XSS</h1>
        <p class="text-secondary mx-auto" style="max-width: 800px;">
            Implementación práctica interactiva basada en el informe oficial de <strong>DVWA (Damn Vulnerable Web Application)</strong>.
            Demostración de explotación controlada y <strong>remediación defensiva</strong> con sentencias preparadas PDO y sanitización.
        </p>
    </div>

    <!-- TARJETAS DE ACCESO A LAS PRÁCTICAS -->
    <div class="row g-4 mb-5">

        <!-- TARJETA 1: Práctica 6.3 - Inyección SQL -->
        <div class="col-lg-4">
            <div class="card-menu border-danger">
                <div class="card-menu-header" style="background: linear-gradient(135deg, #450a0a, #111827);">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span class="badge bg-danger">Sección 6.3</span>
                        <i class="bi bi-terminal fs-3 text-danger"></i>
                    </div>
                    <h4 class="fw-bold text-white m-0">Inyección SQL Manual</h4>
                    <small class="text-danger-emphasis">Ataques basados en UNION y Enumeración</small>
                </div>
                <div class="card-menu-body">
                    <p class="text-secondary small mb-3">
                        Replicación exacta de los pasos de la guía del Licenciado:
                    </p>
                    <ul class="text-secondary small ps-3 mb-0">
                        <li class="mb-1">Detección mediante comilla simple (<code>'</code>).</li>
                        <li class="mb-1">Conteo de columnas con <code>ORDER BY</code> (1, 2 y error en 3).</li>
                        <li class="mb-1">Extracción de versión con <code>UNION SELECT</code>.</li>
                        <li class="mb-1">Enumeración de tablas y columnas (<code>information_schema</code>).</li>
                        <li class="mb-1">Exfiltración de credenciales de la tabla <code>users</code>.</li>
                        <li><strong>Modo Defensivo con PDO Prepared Statements.</strong></li>
                    </ul>
                </div>
                <div class="card-menu-footer">
                    <a href="sqli.php" class="btn btn-danger w-100 fw-bold">
                        <i class="bi bi-box-arrow-in-right me-1"></i> Entrar a Práctica SQLi
                    </a>
                </div>
            </div>
        </div>

        <!-- TARJETA 2: Práctica 6.4 - Cross-Site Scripting (XSS) -->
        <div class="col-lg-4">
            <div class="card-menu border-warning">
                <div class="card-menu-header" style="background: linear-gradient(135deg, #451a03, #111827);">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span class="badge bg-warning text-dark">Sección 6.4</span>
                        <i class="bi bi-code-slash fs-3 text-warning"></i>
                    </div>
                    <h4 class="fw-bold text-white m-0">Ataques XSS</h4>
                    <small class="text-warning-emphasis">Inyección de Scripts y Defacement</small>
                </div>
                <div class="card-menu-body">
                    <p class="text-secondary small mb-3">
                        Pruebas de concepto descritas en el informe oficial:
                    </p>
                    <ul class="text-secondary small ps-3 mb-0">
                        <li class="mb-1">Ventana emergente con <code>alert()</code>.</li>
                        <li class="mb-1">Inclusión de marcos con etiquetas <code>&lt;iframe&gt;</code>.</li>
                        <li class="mb-1">Robo y lectura de cookies con <code>document.cookie</code>.</li>
                        <li class="mb-1">Redirección no autorizada con <code>window.location</code>.</li>
                        <li class="mb-1">Ataque de <strong>Defacement</strong> (XSS-404).</li>
                        <li><strong>Remediación con htmlspecialchars() y CSP.</strong></li>
                    </ul>
                </div>
                <div class="card-menu-footer">
                    <a href="xss.php" class="btn btn-warning text-dark w-100 fw-bold">
                        <i class="bi bi-box-arrow-in-right me-1"></i> Entrar a Práctica XSS
                    </a>
                </div>
            </div>
        </div>

        <!-- TARJETA 3: Fuerza Bruta y Medidas Defensivas -->
        <div class="col-lg-4">
            <div class="card-menu border-info">
                <div class="card-menu-header" style="background: linear-gradient(135deg, #082f49, #111827);">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span class="badge bg-info text-dark">Teoría & Defensa</span>
                        <i class="bi bi-shield-lock fs-3 text-info"></i>
                    </div>
                    <h4 class="fw-bold text-white m-0">Fuerza Bruta & Defensas</h4>
                    <small class="text-info-emphasis">Ataques de Diccionario y Contramedidas</small>
                </div>
                <div class="card-menu-body">
                    <p class="text-secondary small mb-3">
                        Implementación de las medidas de protección citadas en el texto:
                    </p>
                    <ul class="text-secondary small ps-3 mb-0">
                        <li class="mb-1">Bloqueo tras 3 intentos fallidos consecutivos.</li>
                        <li class="mb-1">Retraso temporal progresivo (<em>Rate Limiting</em>).</li>
                        <li class="mb-1">Auditoría de intentos de inicio de sesión por cuenta.</li>
                        <li class="mb-1">Fundamento teórico de MFA y WAF.</li>
                        <li><strong>Simulador interactivo de bloqueo en vivo.</strong></li>
                    </ul>
                </div>
                <div class="card-menu-footer">
                    <a href="fuerza_bruta.php" class="btn btn-info text-dark w-100 fw-bold">
                        <i class="bi bi-box-arrow-in-right me-1"></i> Entrar a Fuerza Bruta
                    </a>
                </div>
            </div>
        </div>

    </div>

    <!-- TABLA DE USUARIOS OFICIALES DE DVWA -->
    <div class="card-menu p-4">
        <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
            <div>
                <h5 class="fw-bold text-white m-0"><i class="bi bi-database text-primary me-2"></i>Base de Datos Oficial de la Guía (Tabla: <code>gsr600.users</code>)</h5>
                <small class="text-secondary">Usuarios registrados con los hashes MD5 que se extraen en la práctica de SQLi</small>
            </div>
            <span class="badge bg-secondary"><?= count($usuarios) ?> Cuentas</span>
        </div>

        <div class="table-responsive">
            <table class="table table-dark table-striped table-bordered table-dark-custom align-middle mb-0">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>first_name</th>
                        <th>last_name</th>
                        <th>user</th>
                        <th>Hash MD5 Almacenado</th>
                        <th>Clave Descifrada (Crackeada)</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $claves = [
                        'admin' => 'password',
                        'gordonb' => 'abc123',
                        '1337' => 'charley',
                        'pablo' => 'letmein',
                        'smithy' => 'password'
                    ];
                    foreach ($usuarios as $u): ?>
                        <tr>
                            <td><?= htmlspecialchars((string)$u['user_id']) ?></td>
                            <td><?= htmlspecialchars($u['first_name']) ?></td>
                            <td><?= htmlspecialchars($u['last_name']) ?></td>
                            <td><span class="badge bg-secondary"><?= htmlspecialchars($u['user']) ?></span></td>
                            <td><code style="color:#f87171; font-size:0.75rem;"><?= htmlspecialchars($u['password']) ?></code></td>
                            <td><span class="badge bg-success"><?= $claves[$u['user']] ?? 'N/A' ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

</div>

</body>
</html>
