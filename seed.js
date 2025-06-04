// seed.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Employee = require('./model/employee'); // adjust path if different

// Sample data
const seedEmployees = [
  {
      employeeId: 'EMP001',
      department: 'IT',
      lastname: 'Santos',
      firstname: 'Juan',
      role: 'super_admin',
      email: 'juan.santos@example.com',
      password: 'hashed_password_1'
    },
    {
      employeeId: 'EMP002',
      department: 'Math',
      lastname: 'Reyes',
      firstname: 'Ana',
      role: 'admin',
      email: 'ana.reyes@example.com',
      password: 'hashed_password_2'
    },
    {
      employeeId: 'EMP003',
      department: 'English',
      lastname: 'Garcia',
      firstname: 'Leo',
      role: 'Faculty',
      email: 'leo.garcia@example.com',
      password: 'hashed_password_3'
    },
    {
      employeeId: 'EMP004',
      department: 'Science',
      lastname: 'Lopez',
      firstname: 'Maria',
      role: 'Faculty',
      email: 'maria.lopez@example.com',
      password: 'hashed_password_4'
    },
    {
      employeeId: 'EMP005',
      department: 'PE',
      lastname: 'Cruz',
      firstname: 'Pedro',
      role: 'Observer',
      email: 'pedro.cruz@example.com',
      password: 'hashed_password_5'
    },
    {
      employeeId: 'EMP006',
      department: 'IT',
      lastname: 'Fernandez',
      firstname: 'Jose',
      role: 'admin',
      email: 'jose.fernandez@example.com',
      password: 'hashed_password_6'
    },
    {
      employeeId: 'EMP007',
      department: 'Math',
      lastname: 'Ramos',
      firstname: 'Celia',
      role: 'Observer',
      email: 'celia.ramos@example.com',
      password: 'hashed_password_7'
    },
    {
      employeeId: 'EMP008',
      department: 'English',
      lastname: 'Torres',
      firstname: 'Luis',
      role: 'Faculty',
      email: 'luis.torres@example.com',
      password: 'hashed_password_8'
    },
    {
      employeeId: 'EMP009',
      department: 'Science',
      lastname: 'Delos Santos',
      firstname: 'Rhea',
      role: 'Faculty',
      email: 'rhea.delos@example.com',
      password: 'hashed_password_9'
    },
    {
      employeeId: 'EMP010',
      department: 'PE',
      lastname: 'Morales',
      firstname: 'Tito',
      role: 'Observer',
      email: 'tito.morales@example.com',
      password: 'hashed_password_10'
    }
];

async function seedDB() {
  try {
    await mongoose.connect('mongodb+srv://copusAdmin:admin12345@cluster0.ugspmft.mongodb.net/copusDB?retryWrites=true&w=majority&appName=copusDB', {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });      
    console.log('✅ Connected to DB');

    await Employee.deleteMany({});
    console.log('🧹 Old employees removed');

    for (let emp of seedEmployees) {
      emp.password = await bcrypt.hash(emp.password, 10); // Hash password
      await Employee.create(emp);
    }

    console.log('🌱 Seed data inserted');
    process.exit();
  } catch (err) {
    console.error('❌ Seeding failed:', err);
    process.exit(1);
  }
}

seedDB();
