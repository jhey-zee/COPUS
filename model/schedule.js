const mongoose = require('mongoose');

const scheduleSchema = new mongoose.Schema({
    employee_id: {type: String, required: true},
    firstname: {type : String, required: true},
    lastname: {type : String, required: true},
    department: {type : String, required: true},
    date: {type : Date, required: true},
    start_time: {type : String, required: true},
    end_time: {type : String, required: true},
    year_level: {type : String, required: true},
    semester: {type : String, enum : ['Semester 1', 'Semester 2'], required: true},
    subject: {type : String, required: true},
    subject_code: {type : String, required: true},
    observer: {type : String, required: true},
    modality: { type: String, enum: ['RAD', 'FLEX'], required: true},
     copus: { type: String, enum: ['Copus 1', 'Copus 2', 'Copus 3'], required: true }, 
    status: {type : String, enum: ['completed', 'cancelled', 'pending'], required: true},
    createdAt: Date,
    updatedAt: Date,
});

module.exports = mongoose.model('schedule', scheduleSchema);