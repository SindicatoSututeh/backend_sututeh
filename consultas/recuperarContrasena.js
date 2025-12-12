// consultas/recuperarContrasena.js
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

// Cargar plantilla HTML para recuperación de contraseña
const recoveryTemplatePath = path.join(__dirname, "../emailTemplates/passwordRecoveryTemplate.html");
const recoveryHtmlTemplate = fs.readFileSync(recoveryTemplatePath, "utf8");

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
router.get('/test-email', async (req, res) => {
  try {
    console.log('🧪 Probando envío con Resend...');
    
    const { data, error } = await resend.emails.send({
      from: 'SUTUTEH <sistema@sututeh.com>',
      to: 'sindicato.sututeh@gmail.com',
      subject: 'Test desde Render - Resend funcionando',
      html: '<h1>✅ Resend funciona!</h1><p>Email enviado correctamente desde Render con tu dominio verificado.</p>',
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
      message: 'Email enviado correctamente con Resend',
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

// ====================================
// 1. Validar reCAPTCHA y verificar existencia del correo
// ====================================
router.post(
  "/verificarCorreoCaptcha",
  [
    body("email").isEmail().withMessage("Correo electrónico inválido"),
    body("tokenCaptcha").notEmpty().withMessage("Token de reCAPTCHA requerido")
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, tokenCaptcha } = req.body;

    try {
      // 1) Validar reCAPTCHA
      const secretKey = process.env.RECAPTCHA_SECRET_KEY;
      const verifyURL = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${tokenCaptcha}`;
      
      const googleRes = await axios.post(verifyURL);
      if (!googleRes.data.success) {
        return res.status(400).json({ error: "reCAPTCHA inválido. Por favor, inténtelo de nuevo." });
      }

      // 2) Verificar que el correo existe y el usuario completó el registro
      const [rows] = await pool.query(
        `SELECT a.id, a.correo_electronico, a.registro_completado, a.estatus
         FROM autenticacion_usuarios a
         WHERE a.correo_electronico = ?`,
        [email.toLowerCase()]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: "No existe una cuenta asociada a este correo electrónico." });
      }

      const user = rows[0];

      if (user.registro_completado !== 1) {
        return res.status(400).json({ error: "Esta cuenta no ha completado el proceso de registro." });
      }

      if (user.estatus !== 'Activo') {
        return res.status(400).json({ error: "Esta cuenta no está activa. Contacte al administrador." });
      }

      res.json({ message: "Correo verificado correctamente." });
    } catch (error) {
      console.error("Error en /verificarCorreoCaptcha:", error);
      res.status(500).json({ error: "Error interno del servidor." });
    }
  }
);

// ====================================
// 2. Enviar código de recuperación
// ====================================
router.post(
  "/enviarCodigo",
  [
    body("email").isEmail().withMessage("Correo electrónico inválido")
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    try {
      // 1) Verificar nuevamente que el usuario existe y está activo
      const [rows] = await pool.query(
        `SELECT a.id, a.correo_electronico, a.registro_completado, a.estatus
         FROM autenticacion_usuarios a
         WHERE a.correo_electronico = ?`,
        [email.toLowerCase()]
      );

      if (rows.length === 0 || rows[0].registro_completado !== 1 || rows[0].estatus !== 'Activo') {
        return res.status(404).json({ error: "Usuario no válido para recuperación de contraseña." });
      }

      const userId = rows[0].id;

      // 2) Generar código OTP de 6 dígitos
      const code = Math.floor(100000 + Math.random() * 900000).toString();

      // 3) Crear token JWT y hashearlo
      const token = jwt.sign({ code }, process.env.JWT_SECRET, { noTimestamp: true });
      const salt = await bcrypt.genSalt(10);
      const hashedToken = await bcrypt.hash(token, salt);

      // 4) Actualizar con el nuevo código de recuperación
      await pool.query(
        `UPDATE autenticacion_usuarios
         SET codigo_verificacion = ?, fecha_codigo_verificacion = NOW()
         WHERE id = ?`,
        [hashedToken, userId]
      );

      // 5) Enviar correo con Resend
      console.log(`📧 Enviando código de recuperación a: ${email}`);
      
      const html = recoveryHtmlTemplate.replace("${codigo}", code);
      
      const { data, error } = await resend.emails.send({
        from: 'SUTUTEH <sistema@sututeh.com>',
        to: email,
        subject: 'Código de Recuperación de Contraseña - SUTUTEH',
        html: html,
      });

      if (error) {
        console.error('❌ Error de Resend:', error);
        return res.status(500).json({ error: "Error al enviar el código de recuperación." });
      }

      console.log(`✅ Email enviado exitosamente. ID: ${data.id}`);
      res.json({ message: "Código de recuperación enviado exitosamente a su correo electrónico." });
    } catch (error) {
      console.error("❌ Error en /enviarCodigo:", error);
      res.status(500).json({ error: "Error interno al enviar el código de recuperación." });
    }
  }
);

// ====================================
// 3. Verificar código de recuperación
// ====================================
router.post(
  "/verificarCodigo",
  [
    body("email").isEmail().withMessage("Correo electrónico inválido"),
    body("codigo").isLength({ min: 6, max: 6 }).withMessage("El código debe tener 6 dígitos")
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, codigo } = req.body;

    try {
      // 1) Buscar usuario y código hasheado
      const [rows] = await pool.query(
        `SELECT a.id, a.codigo_verificacion, a.fecha_codigo_verificacion
         FROM autenticacion_usuarios a
         WHERE a.correo_electronico = ?`,
        [email.toLowerCase()]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const user = rows[0];

      if (!user.codigo_verificacion || !user.fecha_codigo_verificacion) {
        return res.status(400).json({ error: "No se ha solicitado recuperación de contraseña para este usuario." });
      }

      // 2) Verificar expiración (10 minutos)
      const now = new Date();
      const codeDate = new Date(user.fecha_codigo_verificacion);
      const diffMinutes = (now - codeDate) / (1000 * 60);

      if (diffMinutes > 10) {
        return res.status(400).json({ error: "El código ha expirado. Solicite uno nuevo." });
      }

      // 3) Recrear token y verificar
      const candidateToken = jwt.sign({ code: codigo }, process.env.JWT_SECRET, { noTimestamp: true });
      const isMatch = await bcrypt.compare(candidateToken, user.codigo_verificacion);

      if (!isMatch) {
        return res.status(400).json({ error: "Código incorrecto. Verifique e intente nuevamente." });
      }

      res.json({ message: "Código verificado correctamente. Puede proceder a cambiar su contraseña." });
    } catch (error) {
      console.error("Error en /verificarCodigo:", error);
      res.status(500).json({ error: "Error interno al verificar el código." });
    }
  }
);

// ====================================
// 4. Actualizar contraseña
// ====================================
router.post(
  "/actualizarContrasena",
  [
    body("email").isEmail().withMessage("Correo electrónico inválido"),
    body("password").isLength({ min: 8 }).withMessage("La contraseña debe tener al menos 8 caracteres"),
    body("confirmPassword").notEmpty().withMessage("Confirmación de contraseña requerida")
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, confirmPassword } = req.body;

    try {
      // 1) Validar que las contraseñas coincidan
      if (password !== confirmPassword) {
        return res.status(400).json({ error: "Las contraseñas no coinciden." });
      }

      // 2) Validar formato de contraseña
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordRegex.test(password)) {
        return res.status(400).json({ 
          error: "La contraseña debe tener al menos 8 caracteres, incluir mayúsculas, minúsculas, números y caracteres especiales." 
        });
      }

      // 3) Verificar si la contraseña está comprometida
      const isCompromised = await isPasswordPwned(password);
      if (isCompromised) {
        return res.status(400).json({ 
          error: "Esta contraseña ha sido comprometida en filtraciones de datos. Por favor, elija una contraseña diferente." 
        });
      }

      // 4) Buscar usuario
      const [rows] = await pool.query(
        `SELECT a.id, a.codigo_verificacion, a.fecha_codigo_verificacion
         FROM autenticacion_usuarios a
         WHERE a.correo_electronico = ?`,
        [email.toLowerCase()]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const user = rows[0];

      // 5) Verificar que se haya verificado el código recientemente (dentro de 15 minutos)
      if (!user.codigo_verificacion || !user.fecha_codigo_verificacion) {
        return res.status(400).json({ error: "Debe verificar el código de recuperación antes de cambiar la contraseña." });
      }

      const now = new Date();
      const codeDate = new Date(user.fecha_codigo_verificacion);
      const diffMinutes = (now - codeDate) / (1000 * 60);

      if (diffMinutes > 15) {
        return res.status(400).json({ error: "El proceso de recuperación ha expirado. Inicie nuevamente." });
      }

      // 6) Hashear nueva contraseña
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // 7) Actualizar contraseña y limpiar código de verificación
      await pool.query(
        `UPDATE autenticacion_usuarios
         SET contrasena = ?, 
             codigo_verificacion = NULL, 
             fecha_codigo_verificacion = NULL,
             fecha_actualizacion = NOW()
         WHERE id = ?`,
        [hashedPassword, user.id]
      );

      res.json({ message: "Contraseña actualizada exitosamente. Ya puede iniciar sesión con su nueva contraseña." });
    } catch (error) {
      console.error("Error en /actualizarContrasena:", error);
      res.status(500).json({ error: "Error interno al actualizar la contraseña." });
    }
  }
);

module.exports = router;