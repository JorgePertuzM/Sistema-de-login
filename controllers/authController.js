const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../config/db');
const { generateResetPasswordLink } = require('../utils/utils');

// Función para registrar un nuevo usuario
exports.register = (req, res) => {
    const { NombreUsuario, contrasena, contrasenaConfirm, idTipoUsuarioFk, nombreCompleto, emailUsuario } = req.body;

    // Validar que las contraseñas coinciden
    if (contrasena !== contrasenaConfirm) {
        return res.status(400).send('Las contraseñas no coinciden');
    }

    // Verificar si el nombre de usuario o el correo ya existen
    db.query('SELECT NombreUsuario, emailUsuario FROM Tbl_Usuarios WHERE NombreUsuario = ? OR emailUsuario = ?', [NombreUsuario, emailUsuario], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        if (results.length > 0) {
            return res.status(400).send('El nombre de usuario o el correo electrónico ya están en uso');
        }

        // Encriptar la contraseña
        bcrypt.hash(contrasena, 8, (err, hashedPassword) => {
            if (err) {
                console.log(err);
                return res.status(500).send('Error en el servidor');
            }

            // Insertar el nuevo usuario en la base de datos
            db.query('INSERT INTO Tbl_Usuarios SET ?', {
                NombreUsuario: NombreUsuario,
                contrasena: hashedPassword,
                idTipoUsuarioFk: idTipoUsuarioFk,
                nombreCompleto: nombreCompleto,
                emailUsuario: emailUsuario,
                idStatusUsuarioFk: 1 // 1 = Habilitado por defecto
            }, (error, result) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error en el servidor');
                }

                return res.status(201).send('Usuario registrado exitosamente');
            });
        });
    });
};

// Función para mostrar la página de registro con los tipos de usuario
exports.showRegisterPage = (req, res) => {
    db.query('SELECT * FROM Tbl_TipoUsuario', (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        res.render('register', { tiposUsuario: results });
    });
};

// Función para el inicio de sesión de un usuario
exports.login = (req, res) => {
    const { NombreUsuario, contrasena, idTipoUsuarioFk } = req.body;

    // Verificar si el usuario existe
    db.query('SELECT * FROM Tbl_Usuarios WHERE NombreUsuario = ? AND idTipoUsuarioFk = ?', [NombreUsuario, idTipoUsuarioFk], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }
        
        if (results.length === 0) {
            return res.status(401).send('Usuario o rol incorrecto');
        }

        const user = results[0];

        // Comparar la contraseña encriptada
        bcrypt.compare(contrasena, user.contrasena, (err, isMatch) => {
            if (err) {
                console.log(err);
                return res.status(500).send('Error en el servidor');
            }

            if (!isMatch) {
                return res.status(401).send('Contraseña incorrecta');
            }

            // Iniciar sesión y redirigir al perfil
            req.session.user = user;
            return res.redirect('/auth/profile');
        });
    });
};

// Función para mostrar la página de login con los roles
exports.showLoginPage = (req, res) => {
    db.query('SELECT * FROM Tbl_TipoUsuario', (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        res.render('login', { roles: results });
    });
};

// Función para mostrar la página de perfil
exports.showProfilePage = (req, res) => {
    if (!req.session.user) {
        return res.redirect('/auth/login');
    }

    const user = req.session.user;

    // Obtener información adicional del usuario si es necesario
    db.query('SELECT * FROM Tbl_Usuarios WHERE NombreUsuario = ?', [user.NombreUsuario], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        const userInfo = results[0];
        res.render('profile', {
            username: userInfo.NombreUsuario,
            email: userInfo.emailUsuario,
            fullName: userInfo.nombreCompleto,
            userType: userInfo.idTipoUsuarioFk, // Considera usar un mapeo para mostrar el nombre del tipo
            userStatus: userInfo.idStatusUsuarioFk // Considera usar un mapeo para mostrar el estado
        });
    });
};




// Función para el inicio de sesión de un usuario
exports.login = (req, res) => {
    const { NombreUsuario, contrasena, idTipoUsuarioFk } = req.body;

    db.query('SELECT * FROM Tbl_Usuarios WHERE NombreUsuario = ? AND idTipoUsuarioFk = ?', [NombreUsuario, idTipoUsuarioFk], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }
        
        if (results.length === 0) {
            return res.status(401).send('Usuario o rol incorrecto');
        }

        const user = results[0];

        bcrypt.compare(contrasena, user.contrasena, (err, isMatch) => {
            if (err) {
                console.log(err);
                return res.status(500).send('Error en el servidor');
            }

            if (!isMatch) {
                return res.status(401).send('Contraseña incorrecta');
            }

            req.session.user = user; // Almacenar el usuario en la sesión
            return res.redirect('/auth/profile'); // Redirigir a la ruta correcta
        });
    });
};







// Función para mostrar la página de perfil con los datos del usuario
exports.profile = (req, res) => {
    if (!req.session.user) {
        return res.redirect('/auth/login'); // Redirigir si no hay sesión activa
    }

    const user = req.session.user;

    // Obtener los detalles del tipo de usuario y estado
    db.query('SELECT idTipoUsuario, tipoUsuario FROM Tbl_TipoUsuario WHERE idTipoUsuario = ?',
         [user.idTipoUsuarioFk], (error, tipoUsuarioResults) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        db.query('SELECT idStatusUsuario, nombreStatusUsuario FROM Tbl_StatusUsuario WHERE idStatusUsuario = ?', [user.idStatusUsuarioFk], (error, statusUsuarioResults) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error en el servidor');
            }

            const tipoUsuario = tipoUsuarioResults[0];
            const statusUsuario = statusUsuarioResults[0];

            res.render('profile', {
                user,
                tipoUsuario: tipoUsuario ? tipoUsuario.tipoUsuario : 'Desconocido',
                statusUsuario: statusUsuario ? statusUsuario.nombreStatusUsuario : 'Desconocido'
            });
        });
    });

    console.log(tipoUsuario);
};



// Función para cerrar sesión
exports.logout = (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.log(err);
            return res.status(500).send('Error al cerrar sesión');
        }
        res.redirect('/auth/login');
    });
};

// Placeholder para la lógica de restablecimiento de contraseña
exports.resetPassword = (req, res) => {
    res.render('resetpassword');
};


// Mostrar el formulario de restablecimiento de contraseña
exports.showResetPasswordForm = (req, res) => {
    res.render('resetpassword'); // Asegúrate de que el archivo 'resetpassword.ejs' exista en la carpeta 'views'
};


// Manejar el envío del formulario de restablecimiento de contraseña
exports.handleResetPasswordRequest = (req, res) => {
    const { email } = req.body;

    // Buscar el usuario por correo electrónico
    db.query('SELECT * FROM Tbl_Usuarios WHERE emailUsuario = ?', [email], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        if (results.length === 0) {
            return res.status(404).send('Usuario no encontrado');
        }

        const user = results[0];

        // Generar un token de restablecimiento
        const token = crypto.randomBytes(20).toString('hex');

        // Establecer la fecha de expiración en formato DATETIME
        const expires = new Date(Date.now() + 3600000).toISOString().slice(0, 19).replace('T', ' ');

        // Guardar el token en la base de datos
        db.query('INSERT INTO Tbl_Tokens (userId, token, expires) VALUES (?, ?, ?)', [user.idUsuario, token, expires], (error) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error en el servidor');
            }

            // Enviar correo electrónico con el enlace para restablecer la contraseña
            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            });

            const resetLink = generateResetPasswordLink(req.headers.host, token);

            const mailOptions = {
                to: user.emailUsuario,
                from: process.env.EMAIL_USER,
                subject: 'Password Reset',
                text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\nPlease click on the following link, or paste this into your browser to complete the process:\n\n${resetLink}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.`
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error en el servidor');
                }

                res.send('Se ha enviado un enlace para restablecer la contraseña a tu correo electrónico.');
            });
        });
    });
};


exports.showResetPasswordForm = (req, res) => {
    const token = req.params.token;

    // Consultar la base de datos para verificar el token
    db.query('SELECT * FROM Tbl_Tokens WHERE token = ?', [token], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        if (results.length === 0) {
            return res.status(404).send('Token inválido o expirado');
        }

        // Renderizar el formulario de restablecimiento de contraseña
        res.render('resetPassword', { token });
    });
};

exports.handlePasswordReset = (req, res) => {
    const token = req.params.token;
    const { newPassword } = req.body;

    // Verificar el token y actualizar la contraseña
    db.query('SELECT * FROM Tbl_Tokens WHERE token = ?', [token], (error, results) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error en el servidor');
        }

        if (results.length === 0) {
            return res.status(404).send('Token inválido o expirado');
        }

        // Obtener el userId del token
        const userId = results[0].userId;

        // Actualizar la contraseña del usuario
        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        db.query('UPDATE Tbl_Usuarios SET passwordUsuario = ? WHERE idUsuario = ?', [hashedPassword, userId], (error) => {
            if (error) {
                console.log(error);
                return res.status(500).send('Error en el servidor');
            }

            // Eliminar el token usado
            db.query('DELETE FROM Tbl_Tokens WHERE token = ?', [token], (error) => {
                if (error) {
                    console.log(error);
                    return res.status(500).send('Error en el servidor');
                }

                res.send('Contraseña restablecida con éxito');
            });
        });
    });
};


// Muestra la página de restablecimiento de contraseña con token
exports.showSetNewPasswordPage = (req, res) => {
    const { token } = req.params;
    // Verifica si el token es válido y no ha expirado
    db.query('SELECT * FROM Tbl_Tokens WHERE token = ? AND expires > NOW()', [token], (err, results) => {
        if (err) {
            return res.status(500).send('Error en el servidor');
        }
        if (results.length === 0) {
            return res.status(400).send('Token inválido o expirado');
        }
        res.render('setNewPassword', { token });
    });
};

// Maneja el establecimiento de una nueva contraseña
exports.setNewPassword = (req, res) => {
    const { password, confirmPassword, token } = req.body;
    if (password !== confirmPassword) {
        return res.status(400).send('Las contraseñas no coinciden');
    }
    db.query('SELECT userId FROM Tbl_Tokens WHERE token = ?', [token], (err, results) => {
        if (err) {
            return res.status(500).send('Error en el servidor');
        }
        if (results.length === 0) {
            return res.status(400).send('Token inválido');
        }
        const userId = results[0].userId;
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).send('Error en el servidor');
            }
            db.query('UPDATE Tbl_Usuarios SET contrasena = ? WHERE idUsuario = ?', [hashedPassword, userId], (err) => {
                if (err) {
                    return res.status(500).send('Error en el servidor');
                }
                db.query('DELETE FROM Tbl_Tokens WHERE token = ?', [token], (err) => {
                    if (err) {
                        return res.status(500).send('Error en el servidor');
                    }
                    res.send('Contraseña actualizada con éxito');
                });
            });
        });
    });
};


