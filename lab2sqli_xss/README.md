# LABORATORIO 2 — INYECCIÓN SQL (SQLi), XSS Y DEFENSAS WEB

Laboratorio práctico de la asignatura **Seguridad Informática (GSR600)** basado en el informe oficial de **DVWA (*Damn Vulnerable Web Application*)**, enfocado en la auditoría de vulnerabilidades del **OWASP Top 10** y su **remediación defensiva**.

---

## 🛠️ Tecnologías y Entorno

- **PHP:** 8.2+
- **Motor de Base de Datos:** MySQL / MariaDB (XAMPP)
- **Frontend:** Bootstrap 5.3+ y Bootstrap Icons
- **Servidor Web:** Apache en XAMPP (Puerto: `8081`)

---

## 🚀 Acceso Rápido a las Prácticas

- **Portal Principal:** [http://localhost:8081/gsr600/lab2sqli_xss/](http://localhost:8081/gsr600/lab2sqli_xss/)
- **Práctica 6.3 (Inyección SQL Manual):** [http://localhost:8081/gsr600/lab2sqli_xss/sqli.php](http://localhost:8081/gsr600/lab2sqli_xss/sqli.php)
- **Práctica 6.4 (Ataques XSS y Defacement):** [http://localhost:8081/gsr600/lab2sqli_xss/xss.php](http://localhost:8081/gsr600/lab2sqli_xss/xss.php)
- **Fuerza Bruta y Medidas Defensivas:** [http://localhost:8081/gsr600/lab2sqli_xss/fuerza_bruta.php](http://localhost:8081/gsr600/lab2sqli_xss/fuerza_bruta.php)

---

## 🔑 Base de Datos Oficial (Tabla: `users`)

| ID | first_name | last_name | user | Hash MD5 Extraído | Clave Descifrada |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `admin` | `admin` | `admin` | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |
| 2 | `Gordon` | `Brown` | `gordonb` | `e99a18c428cb38d5f260853678922e03` | `abc123` |
| 3 | `Hack` | `Me` | `1337` | `8d3533d75ae2c3966d7e0d4fcc69216b` | `charley` |
| 4 | `Pablo` | `Picasso` | `pablo` | `0d107d09f5bbe40cade3de5c71e9e9b7` | `letmein` |
| 5 | `Bob` | `Smith` | `smithy` | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |

---

## 📁 Estructura del Proyecto

```text
lab2sqli_xss/
│
├── conexion.php        # Conexión centralizada PDO (gsr600)
├── index.php           # Portal principal y selector de módulos
├── sqli.php            # Práctica 6.3: Inyección SQL Manual (Vulnerable vs Seguro con PDO)
├── xss.php             # Práctica 6.4: Pruebas XSS (Vulnerable vs Sanitizado con htmlspecialchars)
├── fuerza_bruta.php    # Módulo de defensa contra ataques de diccionario (Rate Limiting)
├── database.sql        # Script de creación de tabla users con los registros oficiales
├── GUIA.md             # Guía didáctica universitaria con fundamento teórico y defensa
└── README.md           # Resumen general del laboratorio
```

Para la explicación detallada de cada payload inyectado y las respuestas a las preguntas del docente, consulte [GUIA.md](GUIA.md).
