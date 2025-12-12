// testResend.js
require('dotenv').config();
const { Resend } = require('resend');

const RAW_BODY = {
  "Cco": [],
  "cc": [],
  "de": "Reenviar <onboarding@resend.dev>",
  "responderA": [],
  "asunto": "Hola mundo",
  "para": ["20221074@uthh.edu.mx"],
  "html": "<p>¡Felicitaciones por enviar su <strong>primer correo electrónico</strong>!</p><hr /><p style=\"color:#898989;font-size:12px;\">2261 Market Street #5039 - San Francisco, CA 94114</p>",
  "texto": "¡Felicitaciones por enviar tu primer correo electrónico!"
};

// ----------------- Config y validaciones -----------------
if (!process.env.RESEND_API_KEY) {
  console.error('FATAL: RESEND_API_KEY no definida en .env');
  process.exit(1);
}

// crea instancia con trim para evitar espacios invisibles
const resend = new Resend(process.env.RESEND_API_KEY.trim());

// Mapea tu body (español) a los campos que Resend espera (inglés)
function mapBody(raw) {
  const mapped = {
    from: raw.de || 'SUTUTEH <sistema@tudominio.com>',
    to: Array.isArray(raw.para) ? raw.para : (raw.para ? [raw.para] : []),
    subject: raw.asunto || '',
    html: raw.html || '',
    text: raw.texto || ''
  };

  // cc / bcc mapping (Resend usa cc / bcc)
  if (raw.cc && raw.cc.length) mapped.cc = raw.cc;
  if (raw.Cco && raw.Cco.length) mapped.bcc = raw.Cco;

  // responderA -> reply_to (si existe)
  if (raw.responderA && raw.responderA.length) {
    // si es array, tomar el primero; si es objeto string, asignar directo
    mapped.reply_to = Array.isArray(raw.responderA) ? raw.responderA[0] : raw.responderA;
  }

  return mapped;
}

async function runTest() {
  const body = mapBody(RAW_BODY);

  // debug - muestra mapeo (sin exponer claves)
  console.log('Intentando enviar con payload mapeado:', {
    from: body.from,
    to: body.to,
    subject: body.subject,
    hasHtml: !!body.html,
    hasText: !!body.text,
    cc: body.cc || null,
    bcc: body.bcc || null,
    reply_to: body.reply_to || null
  });

  try {
    const result = await resend.emails.send(body);
    console.log('✅ Envío exitoso. ID:', result.id);
    console.log('Respuesta completa:', result);
  } catch (err) {
    console.error('❌ Error al enviar con Resend:');
    console.error('Status:', err.response?.status ?? 'sin status');
    console.error('Body:', JSON.stringify(err.response?.data ?? err.message, null, 2));
    // Si ves 401 -> clave inválida o mal cargada
    // Si ves 422 -> problema con el remitente (from) o email no verificado
    process.exit(1);
  }
}

runTest();
