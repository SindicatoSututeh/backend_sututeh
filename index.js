// Auto-deploy test - CI/CD configurado v3

// index.js
process.env.TZ = 'America/Mexico_City';
require("dotenv").config();
const express        = require("express");
const cors           = require("cors");
const cookieParser   = require("cookie-parser");
const pool           = require("./bd");
const refreshSession = require("./config/refreshSession");
// === CRON AUTOMÁTICO ===




const app = express();
const port = process.env.PORT || 3001;
const path = require('path');


// 1) CORS
app.use(cors({
  origin:    
  [
    //backen local y render
    'http://localhost:3000',
    'http://192.168.100.9:3000',
    'https://backend-sututeh.onrender.com',
    
    'http://192.168.100.9:3001',  // ← AGREGADO

    //hostinger fronthen
    'https://sututeh.com',
    'https://www.sututeh.com',
    'http://localhost:3001',  // ← AGREGADO

  ],
  credentials: true
}));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(express.json());
app.use(cookieParser());

// Agregar esto después de las configuraciones CORS y antes de las rutas
// ENDPOINT DE HEALTH CHECK PARA UPTIMEROBOT
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: 'Servidor SUTUTEH funcionando correctamente',
    uptime: process.uptime()
  });
});
// Ruta principal
app.get("/", (req, res) => {
  res.send("Servidor y API funcionando correctamente");
});


// RUTAS PÚBLICAS (antes de refreshSession)
const registroRoutes            = require('./consultas/registro');
const loginRoutes               = require('./consultas/login');
const recuperarContrasenaRoutes = require("./consultas/recuperarContrasena");
const filosofiaRoutes = require('./consultas/filosofia');
const documentosRegulatoriosRoutes = require('./consultas/documentos_regulatorios');
const datosEmpresaRoutes = require('./consultas/datos_empresa');
const noticiasRouter = require("./consultas/noticias");
const preguntasRouter = require('./consultas/preguntas');
const reunionesRouter  = require('./consultas/reunionesyasistencia');
const puestosRouter = require('./consultas/gestion_puestos');
const encuestasVotacionesRouter = require('./consultas/encuestasVotaciones');
const documentosRouter = require('./consultas/documentos');
const transparenciaRouter = require('./consultas/transparencia');
const rifasRouter = require('./consultas/rifas');
const authCheckRouter = require('./consultas/authCheck');
const verificarUsuarioRoutes = require('./consultas/verificarUsuario');
const gestionUsuariosRouter = require('./consultas/gestion_usuarios');
const mlPrediccionesRouter = require('./consultas/ml_predicciones');
const pagosrouter =require('./consultas/pagos');
const puntosRouter = require("./consultas/puntos");
const logrosRouter = require("./consultas/logros");
const autenticacionMvl = require("./consultas/autenticacionmvl");
const rankingRouter = require('./consultas/ranking');
const dashboardRoutes = require('./consultas/dashboard');
const notificacionesRoutes = require('./consultas/notificaciones');









app.use('/api/registro',            registroRoutes);
app.use('/api/login',               loginRoutes);
app.use('/api/recuperarContrasena', recuperarContrasenaRoutes);
app.use('/api/nosotros', filosofiaRoutes);
app.use('/api/documentos-regulatorios', documentosRegulatoriosRoutes);
app.use('/api/datos-empresa', datosEmpresaRoutes);
app.use("/api/noticias", noticiasRouter);
app.use('/api/preguntas', preguntasRouter);
app.use('/api/reuniones',           reunionesRouter);
app.use('/api/puestos', puestosRouter);
app.use('/api/encuestas-votaciones', encuestasVotacionesRouter);
app.use('/api/documentos', documentosRouter);
app.use('/api/transparencia', transparenciaRouter);
app.use('/api/rifas', rifasRouter);
app.use('/api/verificar-usuario', verificarUsuarioRoutes);
app.use('/api/usuarios', gestionUsuariosRouter);
app.use('/api/ml', mlPrediccionesRouter);
app.use('/api/pagos', pagosrouter);
app.use("/api/puntos", puntosRouter);
app.use("/api/logros", logrosRouter);
app.use("/api/auth/mobile", autenticacionMvl);
app.use('/api/ranking', rankingRouter);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/notificaciones', notificacionesRoutes);
app.use('/api', require('./consultas/asistencia'));
app.use("/api/mobile", require("./consultas/asistencia_mobile"));













// REFRESH DE SESIÓN (renueva JWT si existe)
app.use(refreshSession);
app.use('/api/auth-check', authCheckRouter);

// RUTAS PROTEGIDAS (después de refreshSession)
const perfilRouter = require('./consultas/perfil');
const imgRoutes             = require("./consultas/img");

app.use('/api/perfilAgremiado', perfilRouter);
app.use('/api/img',             imgRoutes);



// Escuchar en todas las interfaces (permite acceso desde tu IP local)
app.listen(port, "0.0.0.0", () => {
  console.log(`Servidor corriendo en http://192.168.100.9:${port}`);
});
