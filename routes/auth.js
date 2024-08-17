const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

// Ruta para mostrar la página de login
router.get('/login', authController.showLoginPage);

// Ruta para manejar el inicio de sesión
router.post('/login', authController.login);

// Ruta para mostrar la página de registro
router.get('/register', authController.showRegisterPage);

// Ruta para manejar el registro de un nuevo usuario
router.post('/register', authController.register);

// Ruta para mostrar la página de restablecimiento de contraseña (pendiente de implementación)
router.get('/resetpassword', authController.resetPassword);

// Ruta para manejar el restablecimiento de contraseña (pendiente de implementación)
//router.post('/resetpassword', authController.resetPassword);

router.post('/resetpassword', authController.handleResetPasswordRequest);

// Ruta para mostrar la página de establecer nueva contraseña con token
router.get('/resetpassword/:token', authController.showSetNewPasswordPage);

// Ruta para mostrar la página de establecer nueva contraseña (pendiente de implementación)
router.get('/set-new-password', authController.setNewPassword);

// Ruta para manejar el establecimiento de una nueva contraseña (pendiente de implementación)
router.post('/set-new-password', authController.setNewPassword);

// Ruta para mostrar la página de perfil (protegida por autenticación)
router.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/auth/login');
    }
    res.render('profile', { user: req.session.user });
});

// Ruta para cerrar sesión
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            return res.status(500).send('Error en el servidor');
        }
        res.redirect('/auth/login');
    });
});

// Ruta para cerrar sesión
router.get('/logout', authController.logout);

module.exports = router;
