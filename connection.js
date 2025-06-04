const mongoose = require('mongoose');

mongoose.connect('mongodb+srv://Daniel:Jxkd937QVovHJsld@test.al3h5.mongodb.net/?retryWrites=true&w=majority&appName=copusDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch((err) => console.error('MongoDB connection error:', err));