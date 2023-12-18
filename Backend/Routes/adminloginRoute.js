const express = require('express');
const { loginAdmin, updatePassword } = require('../Controllers/adminloginController');

const router = express.Router();

router.post('/adminLogin', loginAdmin);
router.post('/changePassword', updatePassword);

module.exports = router;
