// utils.js
const generateResetPasswordLink = (host, token) => {
    return `http://${host}/auth/resetpassword/${token}`;
};

module.exports = {
    generateResetPasswordLink,
};
