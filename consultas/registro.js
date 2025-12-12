// consultas/registro.js
const express = require('express');
const pool = require('../bd');
const router = express.Router();
const { Resend } = require('resend');

const { body, validationResult } = require("express-validator");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const axios = require("axios");

// ====================================
// CONFIGURACIÓN RESEND
// ====================================
const resend = new Resend(process.env.RESEND_API_KEY);

// Cargar plantilla HTML de email
const templatePath = path.join(__dirname, "../emailTemplates/emailtemplate.html");
const htmlTemplate = fs.readFileSync(templatePath, "utf8");

// Función para verificar si la contraseña está comprometida usando la API de Have I Been Pwned
async function isPasswordPwned(password) {
  const sha1Hash = crypto.createHash("sha1")
    .update(password)
    .digest("hex")
    .toUpperCase();
  const prefix = sha1Hash.substring(0, 5);
  const suffix = sha1Hash.substring(5);
  
  try {
    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "User-Agent": "SUTUTEH-App" }
    });
    const lines = response.data.split("\n");
    for (const line of lines) {
      const [hashSuffix, count] = line.split(":");
      if (hashSuffix.trim() === suffix) {
        return parseInt(count.trim(), 10) > 0;
      }
    }
    return false;
  } catch (error) {
    console.error("Error al verificar contraseña en HIBP:", error);
    return false;
  }
}

// ====================================
// ENDPOINT DE PRUEBA
// ====================================
router.get('/test-email-registro', async (req, res) => {
  try {
    console.log('🧪 Probando envío con Resend (Registro)...');
    
    const { data, error } = await resend.emails.send({
      from: 'SUTUTEH <sistema@sututeh.com>',
      to: 'sindicato.sututeh@gmail.com',
      subject: 'Test Registro - Resend funcionando',
      html: '<h1>✅ Resend funciona en Registro!</h1><p>Email enviado correctamente desde el módulo de registro.</p>',
    });

    if (error) {
      console.error('❌ Error de Resend:', error);
      return res.status(500).json({
        ok: false,
        error: error
      });
    }

    console.log('✅ Email enviado:', data.id);
    return res.json({ 
      ok: true, 
      message: 'Email de prueba enviado correctamente con Resend',
      id: data.id 
    });
  } catch (err) {
    console.error('❌ Error:', err);
    return res.status(500).json({
      ok: false,
      error: {
        message: err.message,
        stack: err.stack
      }
    });
  }
});

// Endpoint para validar si la contraseña está comprometida
router.post(
  "/checkPasswordCompromised",
  [ body("password").notEmpty().withMessage("La contraseña es requerida") ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { password } = req.body;
    try {
      const compromised = await isPasswordPwned(password);
      if (compromised) {
        return res.status(400).json({ error: "La contraseña ha sido comprometida. Por favor, elige otra." });
      }
      res.json({ message: "Contraseña segura." });
    } catch (err) {
      console.error("Error en /checkPasswordCompromised:", err);
      res.status(500).json({ error: "Error interno al validar contraseña." });
    }
  }
);

// ====================================
// Enviar código de verificación (OTP)
// ====================================
router.post(
  "/enviarCodigo",
  [
    body("correo_electronico").isEmail().withMessage("Correo inválido"),
    body("fecha_nacimiento").isISO8601().withMessage("Fecha inválida"),
  ],
  async (req, res) => {
    // 0) Validar esquema
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { correo_electronico, fecha_nacimiento } = req.body;

    try {
      // 1) Comprobar que el usuario ya esté preregistrado
      const [rows] = await pool.query(
        `SELECT a.id, a.registro_completado
         FROM autenticacion_usuarios a
         JOIN perfil_usuarios p ON a.id = p.id
         WHERE a.correo_electronico = ?
           AND p.fecha_nacimiento = ?`,
        [correo_electronico.toLowerCase(), fecha_nacimiento]
      );

      // 2) Si no existe, devolvemos 404 y no insertamos nada
      if (rows.length === 0) {
        return res.status(404).json({ error: "Usuario no encontrado" });
      }

      const { id: userId, registro_completado } = rows[0];

      // 3) Si ya completó el registro, no enviamos OTP
      if (registro_completado === 1) {
        console.log("Usuario ya registrado");
        return res.status(400).json({ error: "Usuario ya registrado" });
      }

      // 4) Generar código OTP de 6 dígitos
      const code = Math.floor(100000 + Math.random() * 900000).toString();

      // 5) Crear token JWT (sin timestamp) y hashearlo
      const token = jwt.sign({ code }, process.env.JWT_SECRET, { noTimestamp: true });
      const salt = await bcrypt.genSalt(10);
      const hashedToken = await bcrypt.hash(token, salt);

      // 6) Actualizar la autenticación con el OTP y la fecha actual
      await pool.query(
        `UPDATE autenticacion_usuarios
         SET codigo_verificacion = ?, fecha_codigo_verificacion = NOW()
         WHERE id = ?`,
        [hashedToken, userId]
      );

      // 7) Enviar el correo con Resend
      console.log(`📧 Enviando código de verificación a: ${correo_electronico}`);
      
      const html = htmlTemplate.replace("${codigo}", code);
      
      const { data, error } = await resend.emails.send({
        from: 'SUTUTEH <sistema@sututeh.com>',
        to: correo_electronico,
        subject: 'Tu código de verificación - SUTUTEH',
        html: html,
      });

      if (error) {
        console.error('❌ Error de Resend:', error);
        return res.status(500).json({ error: "Error al enviar el código de verificación." });
      }

      console.log(`✅ Email enviado exitosamente. ID: ${data.id}`);
      res.json({ message: "Código de verificación enviado exitosamente." });
    } catch (err) {
      console.error("❌ Error en /enviarCodigo:", err);
      res.status(500).json({ error: "Error interno al enviar el código." });
    }
  }
);

// ====================================
// Validar código OTP
// ====================================
router.post(
  "/validarCodigo",
  [
    body("correo_electronico").isEmail().withMessage("Correo inválido"),
    body("codigo").isLength({ min: 6, max: 6 }).withMessage("Código debe tener 6 dígitos"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { correo_electronico, codigo } = req.body;
    try {
      // 1) Recuperar hash y timestamp
      const [[user]] = await pool.query(
        `SELECT id, codigo_verificacion AS hashToken, fecha_codigo_verificacion
         FROM autenticacion_usuarios
         WHERE correo_electronico = ?`,
        [correo_electronico.toLowerCase()]
      );
      if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

      // 2) Comprobar expiración (10 minutos)
      if (Date.now() - new Date(user.fecha_codigo_verificacion).getTime() > 10 * 60 * 1000) {
        return res.status(400).json({ error: "El código ha expirado" });
      }

      // 3) Recrear token y comparar
      const candidateToken = jwt.sign({ code: codigo }, process.env.JWT_SECRET, { noTimestamp: true });
      const isMatch = await bcrypt.compare(candidateToken, user.hashToken);
      if (!isMatch) return res.status(400).json({ error: "Código incorrecto" });

      // 4) Marcar como verificado
      await pool.query(
        `UPDATE autenticacion_usuarios
         SET verificado = 1
         WHERE id = ?`,
        [user.id]
      );

      res.json({ message: "Código verificado correctamente." });
    } catch (err) {
      console.error("Error en /validarCodigo:", err);
      res.status(500).json({ error: "Error interno al validar el código." });
    }
  }
);

// ====================================
// Actualizar usuario después de verificado
// ====================================
router.post(
  "/actualizarUsuario",
  [
    body("correo_electronico").isEmail().withMessage("Correo inválido"),
    body("password").isLength({ min: 8 }).withMessage("La contraseña debe tener al menos 8 caracteres"),
    body("firstName").notEmpty().withMessage("Nombre requerido"),
    body("lastName").notEmpty().withMessage("Apellido paterno requerido"),
    body("maternalLastName").notEmpty().withMessage("Apellido materno requerido"),
    body("gender").isIn(["Masculino","Femenino","Otro"]).withMessage("Género inválido"),
    body("curp").isLength({ min: 18, max: 18 }).withMessage("CURP debe tener 18 caracteres"),
    body("phone").isLength({ min: 10, max: 10 }).withMessage("Teléfono debe tener 10 dígitos"),
    body("universityOrigin").isInt().withMessage("Universidad inválida"),
    body("universityPosition").isInt().withMessage("Puesto inválido"),
    body("educationalProgram").optional({ checkFalsy: true, nullable: true }).isInt().withMessage("Programa inválido"),
    body("workerNumber").notEmpty().withMessage("Número de trabajador requerido"),
    body("educationalLevel").isInt().withMessage("Nivel educativo inválido"),
    body("antiguedad").optional({ checkFalsy: true, nullable: true }).isISO8601().withMessage("Fecha de antigüedad inválida"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const {
      correo_electronico,
      password,
      firstName,
      lastName,
      maternalLastName,
      gender,
      curp,
      phone,
      universityOrigin,
      universityPosition,
      educationalProgram,
      workerNumber,
      educationalLevel,
      antiguedad,
    } = req.body;

    try {
      // 1) Buscar al usuario
      const [[user]] = await pool.query(
        "SELECT id FROM autenticacion_usuarios WHERE correo_electronico = ?",
        [correo_electronico.toLowerCase()]
      );
      if (!user) return res.status(404).json({ error: "Usuario no encontrado" });
      const userId = user.id;

      // 2) Hashear contraseña
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // 3) Actualizar autenticación
      await pool.query(
        `UPDATE autenticacion_usuarios
         SET contrasena = ?, registro_completado = 1
         WHERE id = ?`,
        [hashedPassword, userId]
      );

      // 4) Actualizar perfil, asignando rol_sindicato_id = 1 por defecto
      await pool.query(
        `UPDATE perfil_usuarios
         SET nombre            = ?,
             apellido_paterno  = ?,
             apellido_materno  = ?,
             genero            = ?,
             curp              = ?,
             telefono          = ?,
             universidad_id    = ?,
             puesto_id         = ?,
             programa_id       = ?,
             nivel_id          = ?,
             numero_trabajador = ?,
             rol_sindicato_id  = 1,
             antiguedad        = ?
         WHERE id = ?`,
        [
          firstName,
          lastName,
          maternalLastName,
          gender,
          curp,
          phone,
          universityOrigin,
          universityPosition,
          educationalProgram || null,
          educationalLevel,
          workerNumber,
          antiguedad || null,
          userId,
        ]
      );

      res.json({ message: "Usuario actualizado y registro completado." });
    } catch (err) {
      console.error("Error en /actualizarUsuario:", err);
      res.status(500).json({ error: "Error interno al actualizar usuario." });
    }
  }
);

// ====================================
// CATÁLOGOS PARA EL FORMULARIO
// ====================================

// 1. Obtener universidades
router.get('/universidades', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, nombre FROM universidades ORDER BY nombre'
    );
    res.json(rows);
  } catch (err) {
    console.error('Error al consultar universidades:', err);
    res.status(500).json({ error: 'Error al obtener universidades' });
  }
});

// 2. Obtener puestos de universidad
router.get('/puestos', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, nombre FROM puestos_universidad ORDER BY nombre'
    );
    res.json(rows);
  } catch (err) {
    console.error('Error al consultar puestos de universidad:', err);
    res.status(500).json({ error: 'Error al obtener puestos' });
  }
});

// 3. Obtener programas educativos
router.get('/programas', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, nombre FROM programas_educativos ORDER BY nombre'
    );
    res.json(rows);
  } catch (err) {
    console.error('Error al consultar programas educativos:', err);
    res.status(500).json({ error: 'Error al obtener programas educativos' });
  }
});

// 4. Obtener niveles educativos
router.get('/niveles', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, nombre FROM niveles_educativos ORDER BY nombre'
    );
    res.json(rows);
  } catch (err) {
    console.error('Error al consultar niveles educativos:', err);
    res.status(500).json({ error: 'Error al obtener niveles educativos' });
  }
});

// ====================================
// 5. Validar existencia de usuario por correo y fecha de nacimiento
// ====================================
router.post('/validarUsuario', [
  body('correo_electronico')
    .trim()
    .toLowerCase()
    .isEmail()
    .withMessage('Correo electrónico inválido'),
  body('fecha_nacimiento')
    .isISO8601()
    .withMessage('Fecha de nacimiento inválida')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

  const { correo_electronico, fecha_nacimiento } = req.body;

  // Logs detallados para debug
  console.log('🔍 Validando usuario - Datos recibidos:', {
    correo_original: req.body.correo_electronico,
    correo_procesado: correo_electronico,
    fecha_original: req.body.fecha_nacimiento,
    fecha_procesada: fecha_nacimiento,
    fecha_tipo: typeof fecha_nacimiento
  });

  try {
    // Primera consulta: Ver qué hay exactamente en la BD
    console.log('📊 Buscando usuario exacto...');
    const [exactRows] = await pool.query(
      `SELECT 
        a.id, 
        a.correo_electronico, 
        a.registro_completado,
        p.fecha_nacimiento,
        DATE_FORMAT(p.fecha_nacimiento, '%Y-%m-%d') as fecha_formatted
       FROM autenticacion_usuarios AS a
       JOIN perfil_usuarios AS p ON a.id = p.id
       WHERE a.correo_electronico = ?`,
      [correo_electronico]
    );

    console.log('📋 Usuarios con este email:', exactRows);

    // Segunda consulta: Buscar con la fecha específica
    console.log('🎯 Buscando con fecha específica...');
    const [rows] = await pool.query(
      `SELECT 
        a.id, 
        a.correo_electronico, 
        a.registro_completado,
        p.fecha_nacimiento,
        DATE_FORMAT(p.fecha_nacimiento, '%Y-%m-%d') as fecha_formatted
       FROM autenticacion_usuarios AS a
       JOIN perfil_usuarios AS p ON a.id = p.id
       WHERE a.correo_electronico = ?
         AND DATE(p.fecha_nacimiento) = ?`,
      [correo_electronico, fecha_nacimiento]
    );

    console.log('🎯 Resultado con fecha específica:', rows);

    // Si no hay resultados, intentar match más flexible
    if (rows.length === 0 && exactRows.length > 0) {
      console.log('⚠️ Usuario existe pero fecha no coincide');
      
      const [flexibleRows] = await pool.query(
        `SELECT 
          a.id, 
          a.correo_electronico, 
          a.registro_completado
         FROM autenticacion_usuarios AS a
         JOIN perfil_usuarios AS p ON a.id = p.id
         WHERE a.correo_electronico = ?
           AND (
             DATE(p.fecha_nacimiento) = ? OR
             p.fecha_nacimiento = ? OR
             DATE_FORMAT(p.fecha_nacimiento, '%Y-%m-%d') = ?
           )`,
        [correo_electronico, fecha_nacimiento, fecha_nacimiento, fecha_nacimiento]
      );

      if (flexibleRows.length > 0) {
        console.log('✅ Encontrado con búsqueda flexible');
        const { id, registro_completado } = flexibleRows[0];
        
        if (registro_completado === 1) {
          return res.status(400).json({ 
            exists: true, 
            registered: true, 
            message: 'Usuario ya completó el registro' 
          });
        }

        return res.json({ 
          exists: true, 
          registered: false, 
          id 
        });
      }
    }

    // Lógica original
    if (rows.length === 0) {
      console.log('❌ Usuario no encontrado después de todas las pruebas');
      return res.status(404).json({ 
        exists: false, 
        message: 'Usuario no encontrado',
        debug: {
          correo_buscado: correo_electronico,
          fecha_buscada: fecha_nacimiento,
          usuarios_con_email: exactRows.length
        }
      });
    }

    const { id, registro_completado } = rows[0];

    if (registro_completado === 1) {
      console.log('⚠️ Usuario ya completó el registro');
      return res.status(400).json({ 
        exists: true, 
        registered: true, 
        message: 'Usuario ya completó el registro' 
      });
    }

    console.log('✅ Usuario válido para registro');
    return res.json({ 
      exists: true, 
      registered: false, 
      id 
    });

  } catch (err) {
    console.error('❌ Error validando usuario:', err);
    return res.status(500).json({ 
      error: 'Error al validar usuario',
      details: err.message 
    });
  }
});

// ====================================
// Validar reCAPTCHA
// ====================================
router.post("/validarCaptcha", async (req, res) => {
  const { tokenCaptcha } = req.body;
  if (!tokenCaptcha) {
    return res.status(400).json({ error: "Falta el token de reCAPTCHA." });
  }

  try {
    const secretKey = process.env.RECAPTCHA_SECRET_KEY;
    const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${tokenCaptcha}`;

    const googleRes = await axios.post(verifyURL);
    if (!googleRes.data.success) {
      return res.status(400).json({ error: "reCAPTCHA inválido." });
    }

    res.json({ message: "Captcha válido." });
  } catch (error) {
    console.error("Error validando reCAPTCHA:", error);
    res.status(500).json({ error: "Error al validar reCAPTCHA." });
  }
});

module.exports = router;