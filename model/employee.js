const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
  employeeId: { type: String, required: true, unique: true },
  department: String,
  lastname: String,
  firstname: String,
  role: { type: String, enum: ['super_admin', 'admin', 'Observer', 'Faculty'] },
  email: { type: String, required: true, unique: true },
  password: String,
  resetToken: String,
  resetTokenExpiry: Date,
  status: { type: String, default: 'Active' },
  isFirstLogin: {
    type: Boolean,
    default: true
  }
});

module.exports = mongoose.model('employee', employeeSchema);
