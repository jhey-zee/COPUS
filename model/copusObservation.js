const mongoose = require('mongoose');

const copusObservationSchema = new mongoose.Schema({
  scheduleId: { type: mongoose.Schema.Types.ObjectId, ref: 'schedules' },
  copusNumber: { type: Number, required: true },
  studentActions: { type: Map, of: Number },
  teacherActions: { type: Map, of: Number },
  engagementLevels: {
    High: { type: Number, default: 0 },
    Med: { type: Number, default: 0 },
    Low: { type: Number, default: 0 },
  },
  comments: { type: String, default: '' },
  observerId: { type: mongoose.Schema.Types.ObjectId, ref: 'employees', required: true },
  dateSubmitted: { type: Date, default: Date.now }
});

module.exports = mongoose.model('copusobservationresults', copusObservationSchema);