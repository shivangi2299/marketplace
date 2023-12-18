const adminloginModel = require('../Models/adminloginModel');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
dotenv.config();

const generateToken = _id => {
  const jwtKey = process.env.JWT_SECRET_KEY;
  return jwt.sign({ _id }, jwtKey, { expiresIn: '30d' });
};

const loginAdmin = async (req, res) => {
  try {
    const { email, password } = req.body;

    let admin = await adminloginModel.findOne({ email });

    if (!admin)
      return res.status(400).json({
        status: '400',
        message: 'Invalid email or password.',
      });

    const isValidPassword = await bcrypt.compare(password, admin.password);

    if (!isValidPassword)
      return res.status(400).json({
        status: '400',
        message: 'Invalid email or password.',
      });

    const token = generateToken(admin._id);

    admin = await adminloginModel.findOneAndUpdate(
      { _id: admin._id },
      { token: token },
      { new: true }
    );

    res.status(200).json({
      message: 'Login successfully',
      userData: {
        _id: admin._id,
        token,
      },
    });
  } catch (e) {
    res.status(500).json({
      message: e,
    });
  }
};

const updatePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    const userId = '64b34c7fc3aa9d2adc067e35';

    const admin = await adminloginModel.findById(userId);

    const isPasswordMatch = await bcrypt.compare(oldPassword, admin.password);

    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Incorrect old password.' });
    }

    // Hash the new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update the user's password
    await adminloginModel.findByIdAndUpdate(userId, { password: hashedPassword });

    // Create a new JWT token with the updated user data
    const updatedUser = { ...admin._doc, password: hashedPassword };
    const jwtKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(updatedUser, jwtKey, { expiresIn: '1h' });

    res.status(200).json({ message: 'Password changed successfully.', token });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ message: 'An error occurred while changing the password.' });
  }
};

module.exports = { loginAdmin, updatePassword };
