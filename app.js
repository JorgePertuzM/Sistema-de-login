const express = require('express');
const path = require('path');
const session = require('express-session');
const authRoutes = require('./routes/auth');

const app = express();

// Configuraciones de Express
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Configurar sesiones
app.use(session({
    secret: 'Joche.1989-2024',
    resave: false,
    saveUninitialized: false,
}));

// Configurar vistas
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configurar archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Usar rutas de autenticación
app.use('/auth', authRoutes);

// Ruta para la página principal (por ejemplo, redirigir al login)
app.get('/', (req, res) => {
    res.redirect('/auth/login');
});

// Iniciar el servidor
app.listen(3000, () => {
    console.log('Servidor iniciado en http://localhost:3000');
});
