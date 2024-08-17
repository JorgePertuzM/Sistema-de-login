const express = require('express');
const { isAuthenticated } = require('../middleware/auth');
const router = express.Router();

router.get('/', (req, res) => {
    res.render('login');
});

router.get('/register', (req, res) => {
    res.render('register');
});

router.get('/reset-password', (req, res) => {
    res.render('resetPassword');
});

router.get('/set-new-password', (req, res) => {
    res.render('setNewPassword');
});

// Proteger la ruta de perfil
router.get('/profile', isAuthenticated, (req, res) => {
    res.render('profile', { user: req.session.user });
});

module.exports = router;
