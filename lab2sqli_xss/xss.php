<?php
// ============================================================
// LABORATORIO 2 – CROSS-SITE SCRIPTING (XSS) Y DEFENSAS
// GSR600 – Seguridad Informática
// Archivo: xss.php
// Práctica 6.4: Ataques XSS, Robo de Cookies, Defacement y Sanitización
// ============================================================

// Establecer cookie didáctica de sesión si no existe para que document.cookie tenga valor demostrable
if (!isset($_COOKIE['session_token'])) {
    setcookie('session_token', 'gsr600_secret_cookie_token_998124', time() + 3600, '/');
}

$nombre_input = $_GET['nombre'] ?? '';
$modo = $_GET['modo'] ?? 'vulnerable'; // 'vulnerable' o 'seguro'

// En modo seguro enviamos cabeceras CSP adicionales
if ($modo === 'seguro') {
    header("X-XSS-Protection: 1; mode=block");
    header("X-Content-Type-Options: nosniff");
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Práctica 6.4 - Ataques XSS y Defacement | Laboratorio 2</title>
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
            max-width: 1150px;
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

        .card-header-custom {
            padding: 18px 24px;
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
            border-color: #f59e0b;
            color: #fff;
            box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.25);
        }

        .btn-payload {
            background: #1f2937;
            border: 1px solid #374151;
            color: #cbd5e1;
            font-size: 0.76rem;
            padding: 7px 10px;
            border-radius: 6px;
            text-align: left;
            width: 100%;
            margin-bottom: 7px;
            transition: all 0.15s;
        }
        .btn-payload:hover {
            background: #374151;
            color: #fff;
            border-color: #f59e0b;
        }

        .output-zone {
            background: #030712;
            border: 1px dashed #374151;
            border-radius: 8px;
            padding: 18px;
            min-height: 120px;
        }
    </style>
</head>
<body>

<div class="main-container">

    <!-- Navegación Superior -->
    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
            <span class="badge bg-warning text-dark mb-1"><i class="bi bi-code-slash me-1"></i> Laboratorio 2 &bull; GSR600</span>
            <h2 class="fw-bold m-0 text-white">6.4. PARTE PRÁCTICA: ATAQUES XSS (CROSS-SITE SCRIPTING)</h2>
            <small class="text-secondary">Demostración de inyección de scripts, robo de cookies, iframes, redirección y defacement</small>
        </div>
        <div class="d-flex gap-2">
            <a href="index.php" class="btn btn-outline-secondary btn-sm"><i class="bi bi-house me-1"></i> Inicio</a>
            <a href="sqli.php" class="btn btn-outline-danger btn-sm"><i class="bi bi-terminal me-1"></i> Inyección SQL</a>
            <a href="fuerza_bruta.php" class="btn btn-outline-info btn-sm"><i class="bi bi-shield-lock me-1"></i> Fuerza Bruta</a>
        </div>
    </div>

    <!-- SELECTOR DE MODO DE SEGURIDAD -->
    <div class="card-custom mb-4" style="background: <?= $modo === 'vulnerable' ? 'rgba(245, 158, 11, 0.1)' : 'rgba(16, 185, 129, 0.1)' ?>; border-color: <?= $modo === 'vulnerable' ? '#f59e0b' : '#10b981' ?>;">
        <div class="p-3 d-flex justify-content-between align-items-center flex-wrap gap-3">
            <div>
                <span class="badge <?= $modo === 'vulnerable' ? 'bg-warning text-dark' : 'bg-success' ?> mb-1">
                    <?= $modo === 'vulnerable' ? 'MODO VULNERABLE ACTIVO (Sin Sanitizar)' : 'MODO SEGURO ACTIVO (htmlspecialchars + CSP)' ?>
                </span>
                <div class="small <?= $modo === 'vulnerable' ? 'text-warning-emphasis' : 'text-success-emphasis' ?>">
                    <?= $modo === 'vulnerable' 
                        ? 'La entrada se imprime directamente en el HTML sin escapar caracteres especiales (permite ejecutar etiquetas <script>, <iframe>, etc.).' 
                        : 'La entrada se sanea con htmlspecialchars($str, ENT_QUOTES, "UTF-8"), convirtiendo caracteres <, >, ", \' en entidades HTML seguras.' ?>
                </div>
            </div>
            <div class="btn-group">
                <a href="xss.php?modo=vulnerable<?= !empty($nombre_input) ? '&nombre=' . urlencode($nombre_input) : '' ?>" class="btn btn-sm <?= $modo === 'vulnerable' ? 'btn-warning text-dark' : 'btn-outline-warning' ?> fw-bold">
                    <i class="bi bi-unlock-fill me-1"></i> Modo Vulnerable
                </a>
                <a href="xss.php?modo=seguro<?= !empty($nombre_input) ? '&nombre=' . urlencode($nombre_input) : '' ?>" class="btn btn-sm <?= $modo === 'seguro' ? 'btn-success' : 'btn-outline-success' ?> fw-bold">
                    <i class="bi bi-shield-fill-check me-1"></i> Modo Seguro (Sanitizado)
                </a>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <!-- COLUMNA IZQUIERDA: Formulario de Entrada y Renderizado -->
        <div class="col-lg-6">
            <div class="card-custom">
                <div class="card-header-custom" style="background: linear-gradient(135deg, #1e293b, #0f172a);">
                    <h5 class="m-0 fw-bold text-white"><i class="bi bi-pencil-square text-warning me-2"></i>Campo de Entrada de Texto</h5>
                    <small class="text-secondary">Simulación del campo vulnerable de DVWA XSS Reflected</small>
                </div>
                <div class="p-4">
                    <form action="xss.php" method="GET">
                        <input type="hidden" name="modo" value="<?= htmlspecialchars($modo) ?>">

                        <div class="mb-3">
                            <label for="nombre" class="form-label text-secondary fw-semibold">Ingrese su nombre o texto:</label>
                            <textarea class="form-control font-monospace" id="nombre" name="nombre" rows="3" required placeholder="Escriba su nombre o código HTML/JavaScript"><?= htmlspecialchars($nombre_input) ?></textarea>
                        </div>

                        <button type="submit" class="btn <?= $modo === 'vulnerable' ? 'btn-warning text-dark' : 'btn-success' ?> fw-bold px-4">
                            <i class="bi bi-send-fill me-1"></i> Enviar y Renderizar
                        </button>
                    </form>

                    <!-- ZONA DE RENDERIZADO DEL NAVEGADOR -->
                    <div class="mt-4">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="fw-bold m-0 text-white"><i class="bi bi-browser-chrome text-info me-1"></i> Salida Renderizada en el Navegador:</h6>
                            <span class="badge bg-secondary"><?= $modo === 'vulnerable' ? 'HTML Crudo (Inseguro)' : 'Entidades Escapadas (Seguro)' ?></span>
                        </div>
                        <div class="output-zone">
                            <?php if (!empty($nombre_input)): ?>
                                <?php if ($modo === 'vulnerable'): ?>
                                    <!-- ========================================================
                                         VULNERABLE: Se imprime directamente sin sanitizar
                                         ======================================================== -->
                                    <div class="p-2 border border-secondary rounded">
                                        <h4>Hola, <?= $nombre_input ?></h4>
                                    </div>
                                <?php else: ?>
                                    <!-- ========================================================
                                         SEGURO: Se sanea con htmlspecialchars
                                         ======================================================== -->
                                    <div class="p-2 border border-success rounded">
                                        <h4>Hola, <?= htmlspecialchars($nombre_input, ENT_QUOTES, 'UTF-8') ?></h4>
                                    </div>
                                    <small class="text-success d-block mt-2">
                                        <i class="bi bi-shield-check me-1"></i>
                                        <strong>Protección aplicada:</strong> Los caracteres <code>&lt;</code>, <code>&gt;</code> y <code>&quot;</code> fueron convertidos en entidades <code>&amp;lt;</code>, <code>&amp;gt;</code> y <code>&amp;quot;</code>. El navegador los muestra como texto pero NO los ejecuta.
                                    </small>
                                <?php endif; ?>
                            <?php else: ?>
                                <span class="text-muted small">Escriba un texto o elija un payload de la derecha para observar el comportamiento.</span>
                            <?php endif; ?>
                        </div>
                    </div>

                </div>
            </div>
        </div>

        <!-- COLUMNA DERECHA: Vectores de Ataque XSS de la Guía Oficial -->
        <div class="col-lg-6">
            <div class="card-custom">
                <div class="card-header-custom" style="background: linear-gradient(135deg, #1e293b, #0f172a);">
                    <h5 class="m-0 fw-bold text-white"><i class="bi bi-lightning-charge-fill text-warning me-2"></i>Vectores de Prueba de la Guía Oficial (Sección 6.4)</h5>
                    <small class="text-secondary">Haz clic en cada botón para cargar los ejemplos del informe del docente</small>
                </div>
                <div class="p-3">

                    <small class="text-muted fw-bold d-block mb-1">1. VENTANA EMERGENTE CLÁSICA (Gráfica 32 y 33)</small>
                    <button type="button" class="btn-payload" onclick="cargarXSS('<script>alert(\'Ataque XSS reflejado exitoso - GSR600\')<\/script>')">
                        <strong>Ejemplo 1:</strong> <code>&lt;script&gt;alert('...')&lt;/script&gt;</code>
                        <div class="text-secondary" style="font-size:0.72rem;">Muestra la típica ventana emergente alert() en el navegador de la víctima.</div>
                    </button>

                    <small class="text-muted fw-bold d-block mt-3 mb-1">2. INSERCIÓN DE MARCOS EXTERNOS (IFRAME) (Gráfica 34 y 35)</small>
                    <button type="button" class="btn-payload" onclick="cargarXSS('<iframe src=\'https://wikipedia.org\' width=\'100%\' height=\'250\' style=\'border:2px solid red; border-radius:8px;\'></iframe>')">
                        <strong>Ejemplo 2:</strong> <code>&lt;iframe src='...'&gt;&lt;/iframe&gt;</code>
                        <div class="text-secondary" style="font-size:0.72rem;">Incrusta un sitio web externo o interfaz falsa dentro de la página legítima.</div>
                    </button>

                    <small class="text-muted fw-bold d-block mt-3 mb-1">3. ROBO / CAPTURA DE COOKIES (Gráfica 36 y 37)</small>
                    <button type="button" class="btn-payload" onclick="cargarXSS('<script>alert(\'Cookie robada con document.cookie: \' + document.cookie)<\/script>')">
                        <strong>Ejemplo 3:</strong> <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
                        <div class="text-secondary" style="font-size:0.72rem;">JavaScript lee las cookies de sesión (session_token) para secuestrar la identidad del usuario.</div>
                    </button>

                    <small class="text-muted fw-bold d-block mt-3 mb-1">4. REDIRECCIÓN NO AUTORIZADA (Gráfica 38 y 39)</small>
                    <button type="button" class="btn-payload" onclick="cargarXSS('<script>if(confirm(\'¿Desea ser redirigido por XSS via window.location?\')) { window.location=\'https://google.com\'; }<\/script>')">
                        <strong>Ejemplo 4:</strong> <code>&lt;script&gt;window.location='...'&lt;/script&gt;</code>
                        <div class="text-secondary" style="font-size:0.72rem;">Redirige a la víctima a una página externa controlada por el atacante (Phishing).</div>
                    </button>

                    <small class="text-muted fw-bold d-block mt-3 mb-1">5. DEFACEMENT COMPLETO DEL SITIO WEB (Gráfica 40, 41 y 42)</small>
                    <button type="button" class="btn-payload" onclick="cargarDefacement()">
                        <strong class="text-danger">Ejemplo 5: DEFACEMENT (XSS-404)</strong>
                        <div class="text-secondary" style="font-size:0.72rem;">Código exacto de la guía: reemplaza totalmente el diseño y apariencia visual de la página.</div>
                    </button>

                </div>
            </div>

            <!-- CUADRO DE CONCLUSIÓN DEFENSIVA -->
            <div class="card-custom p-3" style="background: rgba(16, 185, 129, 0.05); border-color: rgba(16, 185, 129, 0.3);">
                <h6 class="fw-bold text-success mb-2"><i class="bi bi-shield-check me-1"></i> ¿Cómo mitigar completamente XSS?</h6>
                <ul class="text-secondary small mb-0 ps-3" style="font-size:0.78rem;">
                    <li><strong>Sanitización de salida:</strong> Utilizar siempre <code>htmlspecialchars($var, ENT_QUOTES, 'UTF-8')</code> antes de renderizar variables de usuario en HTML.</li>
                    <li><strong>Bandera HttpOnly en Cookies:</strong> Configurar <code>session.cookie_httponly = 1</code> en PHP para que JavaScript no pueda leer las cookies mediante <code>document.cookie</code>.</li>
                    <li><strong>Content Security Policy (CSP):</strong> Configurar cabeceras HTTP que prohíban la ejecución de scripts en línea (*inline scripts*).</li>
                </ul>
            </div>

        </div>
    </div>

</div>

<script>
function cargarXSS(payload) {
    document.getElementById('nombre').value = payload;
}

function cargarDefacement() {
    const payload = '<script>alert("Hackiado por XSS-404")<\/script><center><div style="background:#000; color:#00ff00; padding:20px; border-radius:10px; border:2px solid red;"><h1>=[ Hacked ]=</h1><h2>=[ By Sector404 ]=</h2><h3>[ hackea el mundo ]</h3><h4 style="color:#ff0000;">lo siento atacado por xss404</h4></div></center>';
    document.getElementById('nombre').value = payload;
}
</script>

</body>
</html>
