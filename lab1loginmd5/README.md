# LABORATORIO 1 — LOGIN VULNERABLE CON MD5

Laboratorio académico de la asignatura **Seguridad Informática (GSR600)** para el estudio de las debilidades y riesgos de seguridad en el almacenamiento de contraseñas mediante la función hash **MD5 sin Salt**.

---

## 🛠️ Tecnologías y Entorno

- **PHP:** 8.2+
- **Motor de Base de Datos:** MySQL / MariaDB (XAMPP)
- **Conector:** PDO con Prepared Statements
- **Frontend:** Bootstrap 5.3+ y Bootstrap Icons
- **Servidor Web:** Apache en XAMPP (Puerto: `8081`)

---

## 🚀 Acceso Rápido

- **URL Local:** [http://localhost:8081/gsr600/lab1loginmd5/](http://localhost:8081/gsr600/lab1loginmd5/)
- **Recuperación de Contraseña:** [http://localhost:8081/gsr600/lab1loginmd5/recuperar.php](http://localhost:8081/gsr600/lab1loginmd5/recuperar.php)
- **Base de Datos:** `gsr600`
- **Script SQL:** [database.sql](database.sql)

---

## 🔑 Credenciales de Prueba (Provistas por el Licenciado)

| Usuario | Email | Contraseña | Rol | Estado | Hash MD5 Almacenado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `admin` | `admin@lab.local` | `123456` | admin | Activo (1) | `e10adc3949ba59abbe56e057f20f883e` |
| `docente` | `docente@lab.local` | `password` | docente | Activo (1) | `5f4dcc3b5aa765d61d8327deb882cf99` |
| `estudiante1` | `estudiante1@lab.local` | `admin123` | estudiante | Activo (1) | `0192023a7bbd73250516f069df18b500` |
| `estudiante2` | `estudiante2@lab.local` | `123456` | estudiante | Activo (1) | `e10adc3949ba59abbe56e057f20f883e` *(Mismo que admin)* |
| `estudiante3` | `estudiante3@lab.local` | `12345678` | estudiante | Activo (1) | `25d55ad283aa400af464c76d713c07ad` |
| `estudiante4` | `estudiante4@lab.local` | `qwerty` | estudiante | **Inactivo (0)** | `d8578edf8458ce06fbc5bb76a58c5ca4` *(Acceso bloqueado)* |
| `invitado` | `invitado@lab.local` | `invitado` | invitado | Activo (1) | `9db2c10e0cdad4ab0b87adf2fc69a35b` |

---

## 📁 Estructura de Archivos

```text
lab1loginmd5/
│
├── conexion.php        # Conexión centralizada PDO a la base de datos MySQL (gsr600)
├── index.php           # Formulario de login, dashboard y laboratorio didáctico
├── recuperar.php       # Módulo interactivo de recuperación con tabla password_resets
├── database.sql        # Script SQL oficial con tablas usuarios y password_resets
├── GUIA.md             # Guía didáctica universitaria con marco teórico y cuestionario
└── README.md           # Descripción general y credenciales
```

Para el desglose de vulnerabilidades, tablas arcoíris y respuestas a la evaluación docente, revise el archivo [GUIA.md](GUIA.md).
