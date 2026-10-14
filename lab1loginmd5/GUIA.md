# GUÍA DIDÁCTICA Y ACADÉMICA — LABORATORIO 1
## "Login Vulnerable con MD5, Ausencia de Salt y Tablas Arcoíris"
### Asignatura: Seguridad Informática (GSR600)

---

## 1. INTRODUCCIÓN HISTÓRICA Y CONTEXTO

La función **MD5 (Message Digest Algorithm 5)** fue diseñada por el criptógrafo **Ronald Rivest** en 1991 (especificada en el **RFC 1321**) para reemplazar a su predecesor MD4.

* **Longitud de salida:** 128 bits (16 bytes), representada universalmente en **32 caracteres hexadecimales**.
* **Objetivo de diseño original:** Ser una función de verificación de integridad rápida para archivos y transferencias de red.
* **El error histórico:** Millones de aplicaciones web durante las décadas de 1990 y 2000 utilizaron `md5($password)` para proteger credenciales en bases de datos MySQL, cometiendo un gravísimo error conceptual al ignorar que **una función de resumen rápido es el peor enemigo de las contraseñas**.

---

## 2. ANÁLISIS DE LAS VULNERABILIDADES DE MD5

En este laboratorio se analizan de manera práctica las cuatro razones por las cuales MD5 está catalogado hoy como **completamente inseguro**:

### 2.1. Ausencia de Salt (Sal Criptográfica)
Cuando una aplicación almacena `md5($password)` de forma directa, contraseñas idénticas producen **hashes matemáticamente idénticos**.

En el script del laboratorio provisto por el Licenciado:
* Usuario `admin`: Contraseña `123456` → Hash: `e10adc3949ba59abbe56e057f20f883e`
* Usuario `estudiante2`: Contraseña `123456` → Hash: `e10adc3949ba59abbe56e057f20f883e`

**Consecuencia para la seguridad:**
Un atacante que obtenga acceso de lectura a la base de datos (por ejemplo, mediante una inyección SQL o una copia de seguridad expuesta) nota inmediatamente que `admin` y `estudiante2` tienen la misma contraseña. Al descifrar la clave del estudiante de bajo rango, compromete de inmediato la cuenta del Administrador.

### 2.2. Vulnerabilidad a Tablas Arcoíris (Rainbow Tables)
Una **Rainbow Table** es una base de datos de búsqueda inversa precalculada que almacena millones de contraseñas comunes junto con sus respectivos hashes.
* Como el hash MD5 sin sal es determinista, "revertir" un hash no requiere calcular nada: solo se realiza una búsqueda de clave-valor que toma **menos de 1 milisegundo**.
* El simulador integrado en el laboratorio demuestra cómo el hash de `123456` es desanonimizado al instante.

### 2.3. Velocidad Excesiva de Cómputo (Fuerza Bruta)
MD5 fue diseñado para ser ultrarrápido en hardware informático:
* Una sola tarjeta gráfica moderna (como una NVIDIA RTX 4090) puede calcular **más de 100,000,000,000 (100 mil millones) de hashes MD5 por segundo** usando software como *Hashcat*.
* Una contraseña alfanumérica de 8 caracteres puede ser crackeada en cuestión de minutos o pocas horas mediante fuerza bruta exhaustiva.

### 2.4. Colisiones Criptográficas Prácticas
En 2004, los investigadores **Xiaoyun Wang, Dengguo Feng, Xuejia Lai y Hongbo Yu** demostraron que es posible encontrar **colisiones prácticas** en MD5 (dos archivos o textos con contenidos totalmente distintos que arrojan el mismo hash). En 2008, esto fue utilizado para crear certificados digitales falsos y comprometer la confianza de la web (ataque Rogue CA).

---

## 3. MECANISMOS EVALUADOS EN EL LABORATORIO

### 3.1. Control de Estado del Usuario (`estado = 0`)
La tabla `usuarios` contiene un campo booleano `estado`:
* `1`: Usuario Activo.
* `0`: Usuario Inactivo / Suspendido.

En el script oficial, el usuario `estudiante4` (clave `qwerty`) tiene `estado = 0`. El sistema implementado valida explícitamente esta condición: si las credenciales son correctas pero el estado es 0, **se deniega el acceso**, impidiendo que usuarios suspendidos operen en la plataforma.

### 3.2. Módulo de Recuperación con Tokens (`password_resets`)
El laboratorio implementa el flujo de restablecimiento de contraseña:
1. El usuario solicita restablecer su cuenta mediante su correo institucional.
2. El servidor genera un token pseudoaleatorio de 64 caracteres hexadecimales (256 bits de entropía) mediante `bin2hex(random_bytes(32))`.
3. Se almacena en la tabla `password_resets` con una fecha de caducidad de 1 hora (`expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR)`).
4. Al utilizar el enlace, el token valida que `used = 0` y no haya caducado, actualizando la clave y marcando `used = 1` para neutralizar ataques de repetición (*Replay Attacks*).

---

## 4. GUÍA DE EJECUCIÓN PASO A PASO

1. **Verificar el Servicio Apache y MySQL:**
   - Asegurarse de que XAMPP tenga Apache y MySQL activos (Apache en el puerto `8081`).
2. **Acceder a la aplicación:**
   - URL: [http://localhost:8081/gsr600/lab1loginmd5/](http://localhost:8081/gsr600/lab1loginmd5/)
3. **Probar el inicio de sesión exitoso:**
   - Clic en el botón rápido `admin / 123456`.
   - Se abrirá la sesión mostrando el panel de bienvenida y el registro de `ultimo_login`.
4. **Probar el bloqueo por cuenta inactiva:**
   - Cerrar sesión y hacer clic en `estudiante4 / qwerty (Inactivo)`.
   - Verificar que el sistema emita una alerta de advertencia: *"Cuenta inactiva o suspendida"*.
5. **Probar el Simulador de Tablas Arcoíris:**
   - En la columna derecha, pegar el hash `5f4dcc3b5aa765d61d8327deb882cf99` y hacer clic en **Buscar**.
   - Se desanonimizará de inmediato la palabra `password`.
6. **Probar la recuperación de contraseña:**
   - Ingresar a [recuperar.php](file:///c:/xampp/htdocs/gsr600/lab1loginmd5/recuperar.php).
   - Solicitar token para `docente@lab.local`, usar el enlace generado y asignar una nueva clave.

---

## 5. CUESTIONARIO Y DEFENSA ANTE EL DOCENTE

**P1: ¿Por qué es una mala práctica utilizar MD5 para almacenar contraseñas de usuarios?**
* **R:** Porque MD5 es una función de resumen sin costo computacional (calculada en nanosegundos), carece de una sal criptográfica automática y fue quebrada matemáticamente en 2004. Permite ataques instantáneos mediante tablas arcoíris y ataques de fuerza bruta masivos a tasas de cientos de miles de millones de hashes por segundo con GPUs modernas.

**P2: ¿Por qué `admin` y `estudiante2` tienen el mismo hash en la base de datos de este laboratorio?**
* **R:** Porque ambos tienen la contraseña `123456` y MD5 es un algoritmo puramente determinista sin salt. Para cualquier entrada `X`, `md5(X)` siempre producirá exactamente el mismo resultado `Y`, permitiendo a un atacante identificar patrones de contraseñas idénticas entre distintos usuarios.

**P3: ¿Cómo soluciona una Salt criptográfica el problema observado en el punto anterior?**
* **R:** La salt es una cadena aleatoria única generada para cada usuario. Si se aplicara una salt (como en Bcrypt o Argon2id), las contraseñas se transformarían en `hash("123456" + salt1)` y `hash("123456" + salt2)`. Aunque la contraseña sea la misma, los hashes resultantes en la base de datos serán completamente distintos, anulando las tablas arcoíris.

**P4: ¿Cuál es el propósito del campo `used` en la tabla `password_resets`?**
* **R:** Evitar ataques de repetición (*Replay Attacks*). Al marcar el token con `used = 1` tras el primer cambio de clave, se garantiza que un enlace de restablecimiento interceptado o reutilizado no pueda volver a comprometer la cuenta.
