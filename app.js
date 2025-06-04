const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');
const User = require('./model/employee');
const Log = require('./model/log');
const Schedule = require('./model/schedule');
const CopusObservation = require('./model/copusObservation'); 
const Appointment = require('./model/Appointment');
const Notification = require('./model/Notification');

const app = express();
const port = 3000;

// MongoDB Connection
mongoose.connect('mongodb+srv://copusAdmin:sK8ZGlLEuWsXavyc@cluster0.ugspmft.mongodb.net/copusDB?retryWrites=true&w=majority&appName=copusDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch((err) => console.error('MongoDB connection error:', err));

// Middleware
app.use(cors());
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); // for form submissions

app.use(session({
  secret: 'blehHAHA', // replace with a secure secret in production
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));

// Set EJS and static files
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Random math question endpoint
app.get('/math-question', (req, res) => {
  const a = Math.floor(Math.random() * 99) + 1; // a: 1–99
  const maxB = 100 - a; // make sure a + b ≤ 100
  const b = Math.floor(Math.random() * maxB) + 1; // b: 1–(100-a)

  res.json({
    a,
    b,
    result: a + b
  });
});

// Public Routes
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});


// Modify this cause i dont tested it yet
const crypto = require('crypto');

app.post('/forgot-password', async (req, res) => {
  const { employeeId } = req.body;

  try {
    const user = await User.findOne({ employeeId });
    if (!user) {
      return res.render('forgot_password_change'); // no user found, still show success page for security
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry
    await user.save();

    req.session.employeeId = employeeId;

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'copus6251@gmail.com',
        pass: 'spgh zwvd qevg oxoe '
      }
    });

    const mailOptions = {
      from: '"Admin" <copus6251@gmail.com>',
      to: user.email,
      subject: 'Password Reset - PHINMA Copus System',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 8px; border: 1px solid #ddd;">
          <h2 style="color: #2c3e50;">Hello ${user.firstname} ${user.lastname},</h2>
          <p>You requested to reset your password. Use the code below to verify your identity:</p>
          <h3 style="color: #e74c3c;">${resetToken}</h3>
          <p>If you did not request this, please ignore this email.</p>
          <p>– PHINMA IT Team</p>
        </div>
      `
    };

    console.log('Sending reset email to:', user.email);
    await transporter.sendMail(mailOptions);
    res.render('forgot_password_change');

  } catch (err) {
    console.error('Forgot password error:', err);
    console.log(err);
  }
});


app.post('/forgot-password-change', async (req, res) => {
  const { resetToken, newPassword } = req.body;
  const employeeId = req.session.employeeId;

  console.log(employeeId);

  if (!employeeId) {
    return res.status(403).send('Session expired. Please try again.');
  }

  try {
    const user = await User.findOne({
      employeeId,
      resetToken,
      resetTokenExpiry: { $gt: Date.now() } // check token not expired
    });

    if (!user) {
      return res.status(400).send('Invalid token or session expired');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    req.session.employeeId = null;

    res.redirect('/login');
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

// Login Handling
app.post('/login', async (req, res) => {
  const { employee, password } = req.body;

  try {
    const foundEmployee = await User.findOne({ employeeId: employee });
    if (!foundEmployee) return res.redirect('/login?error=1');

    const isMatch = await bcrypt.compare(password, foundEmployee.password);
    if (!isMatch) return res.redirect('/login?error=1');

    // Check if employee is active (Comment this part if the login is not working)
    if (foundEmployee.status !== 'Active' && foundEmployee.status !== 'active') {
      return res.render('login', { error: 'Your account is inactive. Please contact admin.' });
    }

    // Store user session
    req.session.user = {
      id: foundEmployee._id,
      role: foundEmployee.role,
      employeeId: foundEmployee.employeeId
    };

    // If not super_admin and it's the first login, redirect to change password
    if (foundEmployee.role !== 'super_admin' && foundEmployee.isFirstLogin) {
      return res.redirect('/change_password');
    }

    console.log(foundEmployee.role);
    // Redirect based on role
    switch (foundEmployee.role) {
      case 'super_admin':
        return res.redirect('/super_admin_dashboard');
      case 'admin':
        return res.redirect('/admin_dashboard');
      case 'Observer':
        return res.redirect('/Observer_dashboard');
      case 'Faculty':
        return res.redirect('/CIT_Faculty_dashboard');
      default:
        return res.redirect('/login?error=1');
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).send('Internal Server Error');
  }
});

// Random math question endpoint
app.get('/math-question', (req, res) => {
  const a = Math.floor(Math.random() * 99) + 1; // a: 1–99
  const maxB = 100 - a; // make sure a + b ≤ 100
  const b = Math.floor(Math.random() * maxB) + 1; // b: 1–(100-a)

  res.json({
    a,
    b,
    result: a + b
  });
});


// Change password after logging in for the first time
app.get('/change_password', isAuthenticated, (req, res) => {
  res.render('change_password'); // Create change_password.ejs in your views
});

app.post('/change_password', isAuthenticated, async (req, res) => {
  const { newPassword } = req.body;

  if (!req.session.user) {
    return res.redirect('/login');
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.findByIdAndUpdate(req.session.user.id, {
      password: hashedPassword,
      isFirstLogin: false
    });

    // Redirect to dashboard based on role
    const user = await User.findById(req.session.user.id);
    switch (user.role) {
      case 'super_admin':
        return res.redirect('/super_admin_dashboard');
      case 'admin':
        return res.redirect('/admin_dashboard');
      case 'Observer':
        return res.redirect('/observer_dashboard');
      case 'Faculty':
        return res.redirect('/CIT_Faculty_dashboard');
      default:
        return res.redirect('/');
    }
  } catch (err) {
    console.error('Password update error:', err);
    return res.status(500).send('Error updating password');
  }
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.status(500).send('Failed to log out.');
    }
    res.redirect('/login');
  });
});

// CIT Faculty Pages
// app.get('/CIT_Faculty_dashboard', isAuthenticated, (req, res) => res.render('CIT_Faculty/dashboard'));

app.get('/CIT_Faculty_copus_result', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login'); // Redirect if user somehow isn't found
    }

    // Fetch schedules where the faculty matches the logged-in user and status is 'completed'
    // ASSUMPTION: Your Schedule model has a field to link it to the faculty,
    // e.g., 'facultyId' or 'facultyName'
    const completedSchedules = await Schedule.find({
      // You'll need to determine how your Schedule model links to the faculty.
      // It could be based on the faculty's full name, ID, or other criteria.
      // For this example, let's assume 'facultyId' in Schedule matches user._id
      // OR 'firstname' and 'lastname' in Schedule match the user's name.
      // If the schedules are meant to be *observed by* the faculty, you might
      // instead use 'observer' field matching user.firstname and user.lastname.
      // Adjust this query to match your database schema:

      // Option 1: If Schedule has a 'facultyId' field linked to the User's _id:
      // facultyId: user._id,

      // Option 2: If the Schedule stores the faculty's full name:
      firstname: user.firstname,
      lastname: user.lastname,

      status: 'completed' // We only want completed observations here
    }).sort({ date: -1, start_time: -1 }); // Sort by newest first

    res.render('CIT_Faculty/copus_result', {
      firstName: user.firstname,    // Pass firstName
      lastName: user.lastname,      // Pass lastName
      employeeId: user.employeeId,  // Pass employeeId
      completedSchedules: completedSchedules // <--- CRUCIAL: Pass the fetched data
    });
  } catch (err) {
    console.error('Error fetching user data or completed schedules for copus_result:', err); // Log the error for debugging
    res.status(500).send('Failed to load Copus Result view');
  }
});
// app.get('/CIT_Faculty_copus_result', isAuthenticated, (req, res) => res.render('CIT_Faculty/copus_result'));

// In app.js or your main routes file
app.get('/CIT_Faculty_copus_result', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login');
    }

    // Fetch all completed schedules for the faculty
    // (Ensure your 'Schedule' model links to the faculty correctly, e.g., by name or ID)
    const completedSchedules = await Schedule.find({
      firstname: user.firstname, // Assuming the schedule stores the observed teacher's first name
      lastname: user.lastname,   // Assuming the schedule stores the observed teacher's last name
      status: 'completed'      // Only completed observations
    }).sort({ date: -1, start_time: -1 }); // Sort by newest first

    res.render('CIT_Faculty/copus_result', {
      firstName: user.firstname,
      lastName: user.lastname,
      employeeId: user.employeeId,
      completedSchedules: completedSchedules // Pass the list of schedules
    });

  } catch (err) {
    console.error('Error fetching completed schedules for CIT_Faculty_copus_result:', err);
    res.status(500).send('Failed to load Faculty Copus Result list.');
  }
});

// In app.js or your main routes file
// In app.js or your main routes file
app.get('/CIT_Faculty_copus_result1/:scheduleId', isAuthenticated, async (req, res) => {
    try {
        const scheduleId = req.params.scheduleId;
        console.log(`Fetching Copus 1 result for scheduleId: ${scheduleId}`);

        const scheduleDetails = await Schedule.findById(scheduleId);
        if (!scheduleDetails) {
            console.warn(`Schedule with ID ${scheduleId} not found.`);
            return res.status(404).send('Schedule details not found.');
        }
        console.log('Schedule Details Copus Type:', scheduleDetails.copus);

        const copusObservation = await CopusObservation.findOne({ scheduleId: scheduleId });
        console.log('CopusObservation found:', copusObservation ? 'Yes' : 'No', copusObservation);

        let tallies = null;
        let engagementPercentages = null;
        let message = null;

        if (copusObservation) {
            console.log('CopusObservation.intervals:', copusObservation.intervals);

            // Ensure studentActions and teacherActions are plain objects if they are Maps in the model
            // This applies to the data *inside* the copusObservation document
            const studentActionsObj = copusObservation.studentActions instanceof Map ? Object.fromEntries(copusObservation.studentActions) : copusObservation.studentActions;
            const teacherActionsObj = copusObservation.teacherActions instanceof Map ? Object.fromEntries(copusObservation.teacherActions) : copusObservation.teacherActions;
            const engagementLevelsObj = copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 };


            if (scheduleDetails.copus === 'Copus 1') {
                 // Your calculateTallies and calculateEngagementPercentages are designed for the 'intervals' array.
                 // The problem is that your POST route for Copus 1 saves direct counts to studentActions, teacherActions, and engagementLevels, not intervals.
                 // This means the GET route for Copus 1 should NOT use calculateTallies/Percentages.
                 // It should directly use the stored studentActions, teacherActions, and engagementLevels.

                tallies = {
                    studentActions: studentActionsObj,
                    teacherActions: teacherActionsObj,
                    // Assuming totalIntervals is the sum of student actions
                    totalIntervals: Object.values(studentActionsObj).reduce((sum, count) => sum + count, 0)
                };

                const totalIntervals = tallies.totalIntervals;
                engagementPercentages = {
                    High: totalIntervals > 0 ? (engagementLevelsObj.High / totalIntervals) * 100 : 0,
                    Med: totalIntervals > 0 ? (engagementLevelsObj.Med / totalIntervals) * 100 : 0,
                    Low: totalIntervals > 0 ? (engagementLevelsObj.Low / totalIntervals) * 100 : 0
                };

                console.log('Calculated Tallies:', tallies);
                console.log('Calculated Engagement Percentages:', engagementPercentages);

            } else {
                message = `This schedule is a ${scheduleDetails.copus} observation, but displayed on Copus 1 result page.`;
            }
        } else {
            message = 'No detailed Copus observation data found for this schedule.';
            console.warn(message);
        }

        res.render('CIT_Faculty/copus_result1', {
            firstName: req.session.user.firstname,
            lastName: req.session.user.lastname,
            employeeId: req.session.user.employeeId,
            scheduleDetails: scheduleDetails,
            tallies: tallies,
            engagementPercentages: engagementPercentages,
            message: message
        });

    } catch (err) {
        console.error('Error retrieving Copus observation results:', err);
        res.status(500).send('Internal Server Error when loading Copus result.');
    }
});

// Display Copus 2 result
app.get('/CIT_Faculty_copus_result2/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 2,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 2 observation found for this schedule.');
    }

    // Fetch schedule details for the view
    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    const tallies = {
      studentActions: copusObservation.studentActions || {},
      teacherActions: copusObservation.teacherActions || {},
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    res.render('CIT_Faculty/copus_result2', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving Copus 2 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Display aggregated Copus 3 result (for all 3 Copus observations for a schedule)
app.get('/CIT_Faculty_copus_result3/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    // Fetch all COPUS observations for the same schedule and observer
    const copusObservations = await CopusObservation.find({
      scheduleId: scheduleId,
      observerId: req.session.user.id
    }).exec();

    if (copusObservations.length === 0) {
      return res.status(404).send('No observations found for this schedule.');
    }

    const aggregatedTallies = {
      studentActions: {},
      teacherActions: {},
      engagementLevels: { High: 0, Med: 0, Low: 0 },
      totalIntervals: 0
    };

    copusObservations.forEach(obs => {
      for (const [action, count] of Object.entries(obs.studentActions || {})) {
        aggregatedTallies.studentActions[action] = (aggregatedTallies.studentActions[action] || 0) + count;
      }

      for (const [action, count] of Object.entries(obs.teacherActions || {})) {
        aggregatedTallies.teacherActions[action] = (aggregatedTallies.teacherActions[action] || 0) + count;
      }

      for (const level of ['High', 'Med', 'Low']) {
        aggregatedTallies.engagementLevels[level] += obs.engagementLevels?.[level] || 0;
      }

      aggregatedTallies.totalIntervals += Object.values(obs.studentActions || {}).reduce((a, b) => a + b, 0);
    });

    const engagementPercentages = {
      High: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.High / aggregatedTallies.totalIntervals) * 100 : 0,
      Med: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Med / aggregatedTallies.totalIntervals) * 100 : 0,
      Low: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Low / aggregatedTallies.totalIntervals) * 100 : 0
    };

    res.render('CIT_Faculty/copus_result3', {
      tallies: aggregatedTallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving aggregated COPUS observations:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Saving the first copus observation and redirect to its result
// Inside your app.post('/observer_copus_result1', ...) route:
app.post('/CIT_Faculty_copus_result1', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId;
    const copusNumber = 1;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

 
    // Alternatively, you can just do:
    const collectedComments = rows.map(row => row.comment).filter(Boolean).join(' ') || 'No comments provided.';


    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: collectedComments, // Use the prepared comments string
      observerId: user.id
    });

    await copusObservation.save();

    res.redirect(`/CIT_Faculty_copus_result1`);
  } catch (err) {
    console.error('Error saving COPUS 1 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Save copus 2 observation and redirect to its result
app.post('/CIT_Faculty_copus_result2', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId; // Retrieve scheduleId from session
    const copusNumber = 2;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: rows.map(row => row.comment).filter(Boolean).join(' '),
      observerId: user.id
    });

    await copusObservation.save();

    // Redirect to the GET route that displays Copus 2 results
    res.redirect(`/CIT_Faculty_copus_result2`); // Redirect to a new GET route for Copus 2 results
  } catch (err) {
    console.error('Error saving COPUS 2 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Save copus 3 observation and mark the schedule as done, then redirect to aggregated result
app.post('/CIT_Faculty_copus_result3', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId; // Retrieve scheduleId from session
    const copusNumber = 3;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

    // Mark the schedule as completed
    const markSched = await Schedule.findById(scheduleId);
    if (markSched) {
      markSched.status = "completed";
      await markSched.save();
    } else {
      console.warn('Schedule not found when trying to mark as completed:', scheduleId);
    }

    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: rows.map(row => row.comment).filter(Boolean).join(' '),
      observerId: user.id
    });

    await copusObservation.save();

    // Redirect to the GET route that displays aggregated Copus results
    res.redirect(`/CIT_Faculty_copus_result3`);
  } catch (err) {
    console.error('Error saving COPUS 3 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// --- Display Observation Results Routes ---

// Display Copus 1 result
// Inside your app.get('/observer_copus_result1', ...) route:
app.get('/CIT_Faculty_copus_result1', isAuthenticated, async (req, res) => {
  try {
    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 1,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 1 observation found for this schedule.');
    }


    const tallies = {
      // Convert Map to plain object using Object.fromEntries()
      studentActions: Object.fromEntries(copusObservation.studentActions || new Map()),
      teacherActions: Object.fromEntries(copusObservation.teacherActions || new Map()),
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    // Calculate total intervals based on the sum of all student action counts
    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    const copusDetails = {
    copusType: `Copus ${copusObservation.copusNumber}` // This assumes copusObservation.copusNumber exists (which it should if copusObservation is found)
};

console.log('Copus 1 Tallies:', tallies);
console.log('Engagement Percentages:', engagementPercentages);
console.log('Copus Details:', copusDetails); // Add this log!

    res.render('CIT_Faculty/copus_result1', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleId: scheduleId,
      copusDetails: copusDetails
    });
  } catch (err) {
    console.error('Error retrieving Copus 1 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});

// IMPORTANT: Apply the same Object.fromEntries() conversion
// to your /observer_copus_result2 and /observer_copus_result3 GET routes as well!

// New: Display Copus 2 result
app.get('/CIT_Faculty_copus_result2', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId; // Get scheduleId from session
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    // Get the latest observation for the current schedule and Copus 2
    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 2,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 2 observation found for this schedule.');
    }

    const tallies = {
      studentActions: copusObservation.studentActions || {},
      teacherActions: copusObservation.teacherActions || {},
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    console.log('Copus 2 Tallies:', tallies);

    // Render the result page for Copus 2
    res.render('CIT_Faculty/copus_result2', { // You'll need to create this EJS file
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (err) {
    console.error('Error retrieving Copus 2 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Display aggregated Copus 3 result (for all 3 Copus observations for a schedule)
app.get('/CIT_Faculty_copus_result3', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId; // Get scheduleId from session
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    // Fetch all COPUS observations for the same schedule and observer
    const copusObservations = await CopusObservation.find({
      scheduleId: scheduleId,
      observerId: req.session.user.id
    }).exec();

    if (copusObservations.length === 0) {
      return res.status(404).send('No observations found for this schedule.');
    }

    const aggregatedTallies = {
      studentActions: {},
      teacherActions: {},
      engagementLevels: { High: 0, Med: 0, Low: 0 },
      totalIntervals: 0
    };

    copusObservations.forEach(obs => {
      for (const [action, count] of Object.entries(obs.studentActions || {})) {
        aggregatedTallies.studentActions[action] = (aggregatedTallies.studentActions[action] || 0) + count;
      }

      for (const [action, count] of Object.entries(obs.teacherActions || {})) {
        aggregatedTallies.teacherActions[action] = (aggregatedTallies.teacherActions[action] || 0) + count;
      }

      for (const level of ['High', 'Med', 'Low']) {
        aggregatedTallies.engagementLevels[level] += obs.engagementLevels?.[level] || 0;
      }

      // Summing up all counts in studentActions to get totalIntervals
      aggregatedTallies.totalIntervals += Object.values(obs.studentActions || {}).reduce((a, b) => a + b, 0);
    });

    // Recalculate percentages based on the aggregated total intervals
    const engagementPercentages = {
      High: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.High / aggregatedTallies.totalIntervals) * 100 : 0,
      Med: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Med / aggregatedTallies.totalIntervals) * 100 : 0,
      Low: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Low / aggregatedTallies.totalIntervals) * 100 : 0
    };

    res.render('CIT_Faculty/copus_result3', { // You'll need to create this EJS file
      tallies: aggregatedTallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (err) {
    console.error('Error retrieving aggregated COPUS observations:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/CIT_Faculty_copus_summary', isAuthenticated, async (req, res) => {
  try {
    // Fetch the current authenticated user's information
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login'); // Redirect if user somehow isn't found
    }

    res.render('IT_Faculty/copus_summary', {
      firstName: user.firstname,  // Pass firstName
      lastName: user.lastname,    // Pass lastName
      employeeId: user.employeeId // Pass employeeId
    });
  } catch (err) {
    console.error('Error fetching user data for copus_result:', err); // Log the error for debugging
    res.status(500).send('Failed to load Copus Result view');
  }
});
//app.get('/CIT_Faculty_copus_summary', isAuthenticated, (req, res) => res.render('CIT_Faculty/copus_summary'));

// In app.js
// In app.js
app.get('/CIT_Faculty_copus_history', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        if (!user) {
            console.warn('User not found in session for CIT Faculty COPUS history. Redirecting to login.');
            return res.redirect('/login');
        }

        // Get the full name of the logged-in faculty member (the one being observed)
        const loggedInFacultyFirstName = user.firstname;
        const loggedInFacultyLastName = user.lastname;

        console.log(`--- CIT_Faculty_copus_history Route Debug ---`);
        console.log(`Logged-in User ID: ${req.session.user.id}`);
        console.log(`Searching for schedules where faculty: "${loggedInFacultyFirstName} ${loggedInFacultyLastName}" was observed, and status: "completed"`);

        // Fetch schedules where the 'firstname' and 'lastname' fields match the logged-in faculty member
        // and the status is 'completed'
        const completedSchedules = await Schedule.find({
            firstname: loggedInFacultyFirstName,
            lastname: loggedInFacultyLastName,
            status: 'completed'
        }).sort({ date: -1, start_time: -1 }); // Sort by most recent date, then start time

        console.log(`Found ${completedSchedules.length} completed schedules for ${loggedInFacultyFirstName} ${loggedInFacultyLastName}.`);
        if (completedSchedules.length === 0) {
            console.log('No schedules matched the criteria for this faculty member.');
        } else {
            console.log('First completed schedule found:', completedSchedules[0]);
        }
        console.log(`--- End Debug ---`);

        res.render('CIT_Faculty/copus_history', {
            firstName: user.firstname,
            lastName: user.lastname,
            employeeId: user.employeeId,
            completedSchedules: completedSchedules // Pass the fetched data
        });
    } catch (err) {
        console.error('Error fetching completed COPUS history for CIT Faculty:', err);
        res.status(500).send('Failed to load COPUS History view.');
    }
});
//app.get('/CIT_Faculty_copus_history', isAuthenticated, (req, res) => res.render('CIT_Faculty/copus_history'));

// app.get('/CIT_Faculty_schedule_management', isAuthenticated, (req, res) => res.render('CIT_Faculty/schedule_management'));

app.get('/CIT_Faculty_setting', isAuthenticated, async (req, res) => {
  try {
    // Fetch the current authenticated user's information
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login'); // Redirect if user somehow isn't found
    }

    // Corrected line: Specify the subdirectory
    res.render('CIT_Faculty/setting', { 
      firstName: user.firstname,      // For sidebar/header
      lastName: user.lastname,        // For sidebar/header
      employeeId: user.employeeId,    // For sidebar 
      currentUser: user               // Pass the full user object for the form details
    });
  } catch (err) {
    console.error('Error fetching user data for settings page:', err); 
    res.status(500).send('Failed to load Settings view'); 
  }
});
//app.get('/CIT_Faculty_setting', isAuthenticated, (req, res) => res.render('CIT_Faculty_setting'));

// CIT Faculty Pages
app.get('/CIT_Faculty_dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    const schedules = await Schedule.find({
      firstname: user.firstname,
      lastname: user.lastname
    });

    const eventMap = {};

    schedules.forEach(sch => {
      const date = new Date(sch.date).toISOString().split('T')[0];
      if (!eventMap[date]) eventMap[date] = [];
      eventMap[date].push(sch);
    });

    const calendarEvents = Object.entries(eventMap).map(([date, scheduleList]) => {
      const total = scheduleList.length;
      const totalCompleted = scheduleList.filter(s => s.status.toLowerCase() === 'completed').length;
      const totalCancelled = scheduleList.filter(s => s.status.toLowerCase() === 'cancelled').length;
      const totalPending = scheduleList.filter(s => s.status.toLowerCase() === 'pending').length;

      let color = 'orange';
      let statusLabel = 'Pending';

      if (totalCompleted === total) {
        color = 'green';
        statusLabel = 'Completed';
      } else if (totalCancelled === total) {
        color = 'red';
        statusLabel = 'Cancelled';
      } else if (totalPending === total) {
        color = 'orange';
        statusLabel = 'Pending';
      } else {
        color = 'blue';
        statusLabel = `${totalCompleted} ✅ / ${totalCancelled} ❌ / ${totalPending} ⏳`;
      }

      return {
        title: statusLabel,
        date,
        color
      };
    });

    // ✅ Now render the view after processing
    res.render('CIT_Faculty/dashboard', {
      employeeId: user.employeeId,
      firstName: user.firstname,
      lastName: user.lastname,
      calendarEvents: JSON.stringify(calendarEvents)
    });

  } catch (err) {
    console.error('Error fetching dashboard data:', err);
    return res.status(500).send('Internal Server Error');
  }
});

const parseDateTime = (dateStr, timeStr) => {
  const [hours, minutes] = timeStr.split(':').map(Number);
  const date = new Date(dateStr);
  date.setHours(hours, minutes, 0, 0);
  return date;
};

app.post('/faculty_create_schedule', isAuthenticated, async (req, res) => {
  const {
    firstname,
    lastname,
    department,
    date,
    start_time,
    end_time,
    year_level,
    semester,
    subject_code,
    subject,
    observer,
    modality,
    copus,
  } = req.body;

  const user = await User.findById(req.session.user.id);  
  const employee_id = user.employeeId;

  try {
    // Convert start_time and end_time to actual Date objects
    const newStart = parseDateTime(date, start_time);
    const newEnd = parseDateTime(date, end_time);

    // Find overlapping schedules for the same observer and approved status
    const conflict = await Schedule.findOne({
      observer,
      date: new Date(date),
      status: 'approved',
    }).then(results => {
      return results && parseDateTime(results.date, results.start_time) < newEnd &&
             parseDateTime(results.date, results.end_time) > newStart;
    });

    if (conflict) {
      const schedules = await Schedule.find({ employee_id }).sort({ timestamp: -1 });
      const observers = await User.find({ $or: [{ role: 'Observer' }, { role: 'super_admin' }] });

      return res.render('CIT_Faculty/schedule_management', {
        schedules,
        observers,
        firstName: user.firstname,
        lastName: user.lastname,
        employeeId: user.employeeId,
        department: user.department,
        errorMessage: 'The selected observer already has an approved appointment at this time.'
      });
    }

    // Save new schedule
    const newSchedule = new Schedule({
      employee_id,
      firstname,
      lastname,
      department,
      date,
      start_time,
      end_time,
      year_level,
      semester,
      subject_code,
      subject,
      observer,
      modality,
      copus,
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date()
    });

    await newSchedule.save();
    
    await Log.create({
      action: 'Create Schedule',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Created a schedule for ${firstname} ${lastname} (Observer: ${observer}). Date: ${date}`
    });

    res.redirect('/CIT_Faculty_schedule_management');
  } catch (err) {
    console.error('Error creating schedule:', err);
    res.redirect('/CIT_Faculty_schedule_management');
  }
});


app.get('/CIT_Faculty_schedule_management', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    const schedules = await Schedule.find({ employee_id: user.employeeId }).sort({ timestamp: -1 });
    // Fetch users with either 'Observer' or 'super_admin' roles
    const observers = await User.find({ $or: [{ role: 'Observer' }, { role: 'super_admin' }] });
    
    res.render('CIT_Faculty/schedule_management', { 
      schedules, 
      observers, 
      firstName: user.firstname, 
      lastName: user.lastname, 
      employeeId: user.employeeId, 
      department: user.department 
    });
  } catch (err) {
    console.error('Error fetching logs:', err);
    res.status(500).send('Failed to load logs');
  }
});

//  In this part the date is not being updated in the database fix it if may time
// Cancel schedule
app.post('/faculty/schedule/cancel/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'cancelled' });
  res.redirect('/CIT_Faculty_schedule_management');
});

// Complete schedule
app.post('/faculty/schedule/complete/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'completed' });
  res.redirect('/CIT_Faculty_schedule_management');
});

// Approve schedule
app.post('/faculty/schedule/approve/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'approved' });
  res.redirect('/CIT_Faculty_schedule_management');
});

// Update schedule
app.post('/faculty/schedule/update/:id', isAuthenticated, async (req, res) => {
  const { firstname, lastname, department, start_time, end_time, year_level, semester, subject, subject_code, observer, modality } = req.body;

  await Schedule.findByIdAndUpdate(req.params.id, {
    firstname,
    lastname,
    department,
    start_time,
    end_time,
    year_level,
    semester,
    subject,
    subject_code,
    observer,
    modality,
    copus,
    updatedAt: new Date()
  });

  res.redirect('/CIT_Faculty_schedule_management');
});


// Observer Dashboard
app.get('/Observer_dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    // Fetch only schedules for the same first and last name
    const name = user.firstname  +" " +user.lastname
    console.log(name);
    const schedules = await Schedule.find({ observer: name });

    console.log(schedules);

    const eventMap = {};

    // Group schedules by date
    schedules.forEach(sch => {
      const date = new Date(sch.date).toISOString().split('T')[0];
      if (!eventMap[date]) eventMap[date] = [];
      eventMap[date].push(sch);
    });

    const calendarEvents = Object.entries(eventMap).map(([date, scheduleList]) => {
      const total = scheduleList.length;
      const totalCompleted = scheduleList.filter(s => s.status.toLowerCase() === 'completed').length;
      const totalCancelled = scheduleList.filter(s => s.status.toLowerCase() === 'cancelled').length;
      const totalPending = scheduleList.filter(s => s.status.toLowerCase() === 'pending').length;

      let color = 'orange';
      let statusLabel = 'Pending';

      if (totalCompleted === total) {
        color = 'green';
        statusLabel = 'Completed';
      } else if (totalCancelled === total) {
        color = 'red';
        statusLabel = 'Cancelled';
      } else if (totalPending === total) {
        color = 'orange';
        statusLabel = 'Pending';
      } else {
        color = 'blue';
        statusLabel = `${totalCompleted} ✅ / ${totalCancelled} ❌ / ${totalPending} ⏳`;
      }

      return {
        title: statusLabel,
        date,
        color
      };
    });

    res.render('Observer/dashboard', {
      employeeId: user.employeeId,
      firstName: user.firstname,
      lastName: user.lastname,
      calendarEvents: JSON.stringify(calendarEvents)
    });

  } catch (err) {
    console.error('Error fetching dashboard data:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/observer_schedule_appointment', async (req, res) => {
  try {
    const { facultyName, appointmentDate, appointmentTime, discussionTopic, observerId, observerName } = req.body; // observerId and observerName might come from session or hidden form fields

    // 1. Find the faculty user to get their ID for the notification
    // This is a simplified example; you might need a more robust way to find the user
    const facultyUser = await User.findOne({ /* query to find user by facultyName, e.g., if name is unique or combine with department */ });

    if (!facultyUser) {
      // Handle case where faculty user is not found
      // You might set req.flash or pass error to render
      req.session.errorMessage = 'Faculty member not found.'; // Example using connect-flash or session
      return res.redirect('/Observer_copus_result'); // Or wherever your observer page is
    }

    // 2. Create and save the new appointment
    const newAppointment = new Appointment({
      facultyName, // Or facultyUser.fullName if you store it that way
      observerName, // Name of the observer who scheduled
      appointmentDate,
      appointmentTime,
      discussionTopic,
      scheduledBy: observerId, // Actual ID of the observer
      facultyMember: facultyUser._id // Actual ID of the faculty member
    });
    await newAppointment.save();

    // 3. Create a notification for the faculty member
    const notificationMessage = `New appointment scheduled by ${observerName} on ${new Date(appointmentDate).toLocaleDateString()} at ${appointmentTime}. Topic: ${discussionTopic || 'Not specified'}`;
    const newNotification = new Notification({
      userId: facultyUser._id,
      message: notificationMessage,
      // link: `/faculty/appointments/${newAppointment._id}` // Optional: link to view appointment
    });
    await newNotification.save();

    // 4. Send success response (e.g., redirect with a success message)
    req.session.successMessage = 'Appointment scheduled successfully and faculty notified!';
    res.redirect('/Observer_copus_result');

  } catch (error) {
    console.error('Error scheduling appointment:', error);
    req.session.errorMessage = 'Failed to schedule appointment. Please try again.';
    res.redirect('/Observer_copus_result');
  }
});

app.post('/api/notifications', /* ensureAuthenticated, ensureFaculty, */ async (req, res) => {
  try {
    // Assuming req.user contains the logged-in user's details (e.g., from Passport.js)
    const notifications = await Notification.find({ userId: req.user._id, isRead: false }) // Fetch unread notifications
                                          .sort({ createdAt: -1 }); // Show newest first
    const unreadCount = await Notification.countDocuments({ userId: req.user._id, isRead: false });

    res.json({ notifications, unreadCount });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: 'Failed to fetch notifications' });
  }
});

// POST /api/notifications/mark-read (optional: to mark notifications as read)
app.post('/api/notifications/mark-read', /* ensureAuthenticated, ensureFaculty, */ async (req, res) => {
  try {
    // const { notificationIds } = req.body; // Array of notification IDs to mark as read
    // await Notification.updateMany({ userId: req.user._id, _id: { $in: notificationIds } }, { $set: { isRead: true } });
    // OR simply mark all as read when the modal is opened for simplicity:
    await Notification.updateMany({ userId: req.user._id, isRead: false }, { $set: { isRead: true } });
    res.json({ message: 'Notifications marked as read' });
  } catch (error) {
    console.error('Error marking notifications as read:', error);
    res.status(500).json({ message: 'Failed to mark notifications as read' });
  }
});



app.get('/Observer_schedule_management', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    const name = user.firstname  + " " + user.lastname
    const schedules = await Schedule.find({ observer: name }).sort({ timestamp: -1 });
    console.log(schedules)
    res.render('Observer/schedule_management', { schedules, firstName : user.firstname, lastName : user.lastname, employeeId : user.employeeId });
  } catch (err) {
    console.error('Error fetching logs:', err); 
    res.status(500).send('Failed to load logs');
  }
});

// Cancel schedule
app.post('/observer/schedule/cancel/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'cancelled' });
  res.redirect('/Observer_schedule_management');
});

// Complete schedule
app.post('/observer/schedule/complete/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'completed' });
  res.redirect('/Observer_schedule_management');
});

// Approve schedule
app.post('/observer/schedule/approve/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'approved' });
  res.redirect('/Observer_schedule_management');
});

// Add a new route to fetch and display completed schedules
app.get('/observer_copus_result', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        if (!user) return res.redirect('/login');

        const completedSchedules = await Schedule.find({
            observer: user.firstname + " " + user.lastname,
            status: 'completed'
        }).sort({ date: -1, start_time: -1 })
          .select('firstname lastname department date start_time end_time year_level semester subject_code subject observer copus modality');

        // Retrieve messages from session
        const successMessage = req.session.successMessage;
        const errorMessage = req.session.errorMessage;

        // Clear the messages from session after retrieving them
        delete req.session.successMessage;
        delete req.session.errorMessage;

        res.render('Observer/copus_result', {
            completedSchedules: completedSchedules,
            firstName: user.firstname,
            lastName: user.lastname,
            user: user,
            employeeId: user.employeeId,
            successMessage: successMessage, // Pass the success message
            errorMessage: errorMessage     // Pass the error message
        });
    } catch (err) {
        console.error('Error fetching completed schedules for Copus Result:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/observer_copus', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    // Fetch all the necessary fields from the schedules where the observer matches and status is 'approved'
    const schedules = await Schedule.find(
      { observer: user.firstname + " " + user.lastname, status: 'approved' }
    )
    .select('firstname lastname department date start_time end_time year_level semester subject_code subject observer copus modality ');

    res.render('Observer/copus', {
      schedules: schedules, // Pass schedules to the view
      firstName: user.firstname,
      lastName: user.lastname,
      employeeId: user.employeeId
    });
  } catch (err) {
    console.error('Error fetching approved schedules:', err);
    res.status(500).send('Internal Server Error');
  }
});




// --- Start Observation Routes (Corrected and Specific) ---

// Route for starting Copus 1 observation
app.get('/observer_copus_start_copus1/:scheduleId', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.params.scheduleId;

    const schedule = await Schedule.findById(scheduleId);

    if (!schedule) {
      return res.status(404).send('Schedule not found');
    }

    req.session.scheduleId = scheduleId; // Store scheduleId in session

    const copusDetails = {
      fullname: `${schedule.firstname} ${schedule.lastname}`,
      department: schedule.department,
      date: new Date(schedule.date).toLocaleDateString(),
      startTime: schedule.start_time,
      endTime: schedule.end_time,
      yearLevel: schedule.year_level,
      semester: schedule.semester,
      subjectCode: schedule.subject_code,
      subjectName: schedule.subject,
      mode: schedule.modality,
      observer: schedule.observer,
      copusType: schedule.copus
    };

    console.log(`Starting Copus 1 for schedule ID: ${scheduleId}`);

    // Render the view for Copus 1
    res.render('Observer/copus_start', { // Corrected view name
      copusDetails,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (error) {
    console.error('Error fetching schedule for Copus 1:', error);
    res.status(500).send('Internal server error');
  }
});

// Route for starting Copus 2 observation
app.get('/observer_copus_start_copus2/:scheduleId', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.params.scheduleId;

    const schedule = await Schedule.findById(scheduleId);

    if (!schedule) {
      return res.status(404).send('Schedule not found');
    }

    req.session.scheduleId = scheduleId; // Store scheduleId in session

    const copusDetails = {
      fullname: `${schedule.firstname} ${schedule.lastname}`,
      department: schedule.department,
      date: new Date(schedule.date).toLocaleDateString(),
      startTime: schedule.start_time,
      endTime: schedule.end_time,
      yearLevel: schedule.year_level,
      semester: schedule.semester,
      subjectCode: schedule.subject_code,
      subjectName: schedule.subject,
      mode: schedule.modality,
      observer: schedule.observer,
      copusType: schedule.copus
    };

    console.log(`Starting Copus 2 for schedule ID: ${scheduleId}`);

    // Render the view for Copus 2
    res.render('Observer/copus_start2', { // Corrected view name
      copusDetails,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (error) {
    console.error('Error fetching schedule for Copus 2:', error);
    res.status(500).send('Internal server error');
  }
});

// Route for starting Copus 3 observation
app.get('/observer_copus_start_copus3/:scheduleId', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.params.scheduleId;

    const schedule = await Schedule.findById(scheduleId);

    if (!schedule) {
      return res.status(404).send('Schedule not found');
    }

    req.session.scheduleId = scheduleId; // Store scheduleId in session

    const copusDetails = {
      fullname: `${schedule.firstname} ${schedule.lastname}`,
      department: schedule.department,
      date: new Date(schedule.date).toLocaleDateString(),
      startTime: schedule.start_time,
      endTime: schedule.end_time,
      yearLevel: schedule.year_level,
      semester: schedule.semester,
      subjectCode: schedule.subject_code,
      subjectName: schedule.subject,
      mode: schedule.modality,
      observer: schedule.observer,
      copusType: schedule.copus
    };

    console.log(`Starting Copus 3 for schedule ID: ${scheduleId}`);

    // Render the view for Copus 3
    res.render('Observer/copus_start3', { // Corrected view name
      copusDetails,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (error) {
    console.error('Error fetching schedule for Copus 3:', error);
    res.status(500).send('Internal server error');
  }
});

// --- Save Observation Data Routes ---

// Display Copus 1 result
app.get('/observer_copus_result1/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 1,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 1 observation found for this schedule.');
    }

    // You might also want to fetch the schedule details here to display on the result page
    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    const tallies = {
      studentActions: Object.fromEntries(copusObservation.studentActions || new Map()),
      teacherActions: Object.fromEntries(copusObservation.teacherActions || new Map()),
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    const copusDetails = {
      copusType: `Copus ${copusObservation.copusNumber}`
    };

    res.render('Observer/copus_result1', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleId: scheduleId,
      copusDetails: copusDetails,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving Copus 1 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Display Copus 2 result
app.get('/observer_copus_result2/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 2,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 2 observation found for this schedule.');
    }

    // Fetch schedule details for the view
    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    const tallies = {
      studentActions: copusObservation.studentActions || {},
      teacherActions: copusObservation.teacherActions || {},
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    res.render('Observer/copus_result2', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving Copus 2 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Display aggregated Copus 3 result (for all 3 Copus observations for a schedule)
app.get('/observer_copus_result3/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    // Fetch all COPUS observations for the same schedule and observer
    const copusObservations = await CopusObservation.find({
      scheduleId: scheduleId,
      observerId: req.session.user.id
    }).exec();

    if (copusObservations.length === 0) {
      return res.status(404).send('No observations found for this schedule.');
    }

    const aggregatedTallies = {
      studentActions: {},
      teacherActions: {},
      engagementLevels: { High: 0, Med: 0, Low: 0 },
      totalIntervals: 0
    };

    copusObservations.forEach(obs => {
      for (const [action, count] of Object.entries(obs.studentActions || {})) {
        aggregatedTallies.studentActions[action] = (aggregatedTallies.studentActions[action] || 0) + count;
      }

      for (const [action, count] of Object.entries(obs.teacherActions || {})) {
        aggregatedTallies.teacherActions[action] = (aggregatedTallies.teacherActions[action] || 0) + count;
      }

      for (const level of ['High', 'Med', 'Low']) {
        aggregatedTallies.engagementLevels[level] += obs.engagementLevels?.[level] || 0;
      }

      aggregatedTallies.totalIntervals += Object.values(obs.studentActions || {}).reduce((a, b) => a + b, 0);
    });

    const engagementPercentages = {
      High: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.High / aggregatedTallies.totalIntervals) * 100 : 0,
      Med: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Med / aggregatedTallies.totalIntervals) * 100 : 0,
      Low: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Low / aggregatedTallies.totalIntervals) * 100 : 0
    };

    res.render('Observer/copus_result3', {
      tallies: aggregatedTallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving aggregated COPUS observations:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Saving the first copus observation and redirect to its result
// Inside your app.post('/observer_copus_result1', ...) route:
app.post('/observer_copus_result1', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId;
    const copusNumber = 1;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

 
    // Alternatively, you can just do:
    const collectedComments = rows.map(row => row.comment).filter(Boolean).join(' ') || 'No comments provided.';


    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: collectedComments, // Use the prepared comments string
      observerId: user.id
    });

    await copusObservation.save();

    res.redirect(`/observer_copus_result1`);
  } catch (err) {
    console.error('Error saving COPUS 1 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Save copus 2 observation and redirect to its result
app.post('/observer_copus_result2', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId; // Retrieve scheduleId from session
    const copusNumber = 2;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: rows.map(row => row.comment).filter(Boolean).join(' '),
      observerId: user.id
    });

    await copusObservation.save();

    // Redirect to the GET route that displays Copus 2 results
    res.redirect(`/observer_copus_result2`); // Redirect to a new GET route for Copus 2 results
  } catch (err) {
    console.error('Error saving COPUS 2 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Save copus 3 observation and mark the schedule as done, then redirect to aggregated result
app.post('/observer_copus_result3', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId; // Retrieve scheduleId from session
    const copusNumber = 3;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

    // Mark the schedule as completed
    const markSched = await Schedule.findById(scheduleId);
    if (markSched) {
      markSched.status = "completed";
      await markSched.save();
    } else {
      console.warn('Schedule not found when trying to mark as completed:', scheduleId);
    }

    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: rows.map(row => row.comment).filter(Boolean).join(' '),
      observerId: user.id
    });

    await copusObservation.save();

    // Redirect to the GET route that displays aggregated Copus results
    res.redirect(`/observer_copus_result3`);
  } catch (err) {
    console.error('Error saving COPUS 3 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// --- Display Observation Results Routes ---

// Display Copus 1 result
// Inside your app.get('/observer_copus_result1', ...) route:
app.get('/observer_copus_result1', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId;
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 1,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 1 observation found for this schedule.');
    }


    const tallies = {
      // Convert Map to plain object using Object.fromEntries()
      studentActions: Object.fromEntries(copusObservation.studentActions || new Map()),
      teacherActions: Object.fromEntries(copusObservation.teacherActions || new Map()),
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    // Calculate total intervals based on the sum of all student action counts
    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    const copusDetails = {
    copusType: `Copus ${copusObservation.copusNumber}` // This assumes copusObservation.copusNumber exists (which it should if copusObservation is found)
};

console.log('Copus 1 Tallies:', tallies);
console.log('Engagement Percentages:', engagementPercentages);
console.log('Copus Details:', copusDetails); // Add this log!

    res.render('Observer/copus_result1', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleId: scheduleId,
      copusDetails: copusDetails
    });
  } catch (err) {
    console.error('Error retrieving Copus 1 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});

// IMPORTANT: Apply the same Object.fromEntries() conversion
// to your /observer_copus_result2 and /observer_copus_result3 GET routes as well!

// New: Display Copus 2 result
app.get('/observer_copus_result2', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId; // Get scheduleId from session
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    // Get the latest observation for the current schedule and Copus 2
    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 2,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 2 observation found for this schedule.');
    }

    const tallies = {
      studentActions: copusObservation.studentActions || {},
      teacherActions: copusObservation.teacherActions || {},
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    console.log('Copus 2 Tallies:', tallies);

    // Render the result page for Copus 2
    res.render('Observer/copus_result2', { // You'll need to create this EJS file
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (err) {
    console.error('Error retrieving Copus 2 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Display aggregated Copus 3 result (for all 3 Copus observations for a schedule)
app.get('/observer_copus_result3', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId; // Get scheduleId from session
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    // Fetch all COPUS observations for the same schedule and observer
    const copusObservations = await CopusObservation.find({
      scheduleId: scheduleId,
      observerId: req.session.user.id
    }).exec();

    if (copusObservations.length === 0) {
      return res.status(404).send('No observations found for this schedule.');
    }

    const aggregatedTallies = {
      studentActions: {},
      teacherActions: {},
      engagementLevels: { High: 0, Med: 0, Low: 0 },
      totalIntervals: 0
    };

    copusObservations.forEach(obs => {
      for (const [action, count] of Object.entries(obs.studentActions || {})) {
        aggregatedTallies.studentActions[action] = (aggregatedTallies.studentActions[action] || 0) + count;
      }

      for (const [action, count] of Object.entries(obs.teacherActions || {})) {
        aggregatedTallies.teacherActions[action] = (aggregatedTallies.teacherActions[action] || 0) + count;
      }

      for (const level of ['High', 'Med', 'Low']) {
        aggregatedTallies.engagementLevels[level] += obs.engagementLevels?.[level] || 0;
      }

      // Summing up all counts in studentActions to get totalIntervals
      aggregatedTallies.totalIntervals += Object.values(obs.studentActions || {}).reduce((a, b) => a + b, 0);
    });

    // Recalculate percentages based on the aggregated total intervals
    const engagementPercentages = {
      High: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.High / aggregatedTallies.totalIntervals) * 100 : 0,
      Med: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Med / aggregatedTallies.totalIntervals) * 100 : 0,
      Low: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Low / aggregatedTallies.totalIntervals) * 100 : 0
    };

    res.render('Observer/copus_result3', { // You'll need to create this EJS file
      tallies: aggregatedTallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (err) {
    console.error('Error retrieving aggregated COPUS observations:', err);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/observer_copus_summary',isAuthenticated, (req, res) => res.render('Observer/copus_summary'));
// Add or modify this route in your Node.js application
app.get('/Observer_copus_history', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login');
    }

    const observerFullName = `${user.firstname} ${user.lastname}`;

    // Fetch schedules that are completed and where the observer matches the logged-in user
    const completedSchedules = await Schedule.find({
      observer: observerFullName,
      status: 'completed' // Filter for completed schedules
    }).sort({ date: -1, start_time: -1 }); // Sort by most recent date, then start time

    res.render('Observer/copus_history', {
      completedSchedules: completedSchedules,
      firstName: user.firstname,
      lastName: user.lastname,
      employeeId: user.employeeId
    });
  } catch (err) {
    console.error('Error fetching completed COPUS history:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/bserver_schedule_management', isAuthenticated, async (req, res) => {
  try {
    // Fetch the current authenticated user's information
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login'); // Redirect if user somehow isn't found
    }

    res.render('Observer/schedule_management', {
      firstName: user.firstname,  // Pass firstName
      lastName: user.lastname,    // Pass lastName
      employeeId: user.employeeId // Pass employeeId
    });
  } catch (err) {
    console.error('Error fetching user data for copus_result:', err); // Log the error for debugging
    res.status(500).send('Failed to load Copus Result view');
  }
});
//app.get('/observer_schedule_management',isAuthenticated, (req, res) => res.render('Observer/schedule_management'));

app.get('/observer_setting', isAuthenticated, async (req, res) => {
  try {
    // Fetch the current authenticated user's information
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login'); // Redirect if user somehow isn't found
    }

    res.render('Observer/setting', {
      firstName: user.firstname,         // For sidebar/header
      lastName: user.lastname,          // For sidebar/header
      employeeId: user.employeeId,      // For sidebar
      currentUser: user                 // Pass the full user object for the form details
    });
  } catch (err) {
    console.error('Error fetching user data for settings page:', err); // Corrected log message
    res.status(500).send('Failed to load Settings view'); // Corrected error message
  }
});
//app.get('/observer_setting',isAuthenticated, (req, res) => res.render('Observer/setting'));

// Admin Pages
app.get('/admin_dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    const schedules = await Schedule.find({});
    const eventMap = {};

    // Group schedules by date
    schedules.forEach(sch => {
      const date = new Date(sch.date).toISOString().split('T')[0];
      if (!eventMap[date]) eventMap[date] = [];
      eventMap[date].push(sch);
    });

    const calendarEvents = Object.entries(eventMap).map(([date, scheduleList]) => {
      const total = scheduleList.length;

      const totalCompleted = scheduleList.filter(s => s.status.toLowerCase() === 'completed').length;
      const totalCancelled = scheduleList.filter(s => s.status.toLowerCase() === 'cancelled').length;
      const totalPending = scheduleList.filter(s => s.status.toLowerCase() === 'pending').length;

      let color = 'orange';
      let statusLabel = 'Pending';

      if (totalCompleted === total) {
        color = 'green';
        statusLabel = 'Completed';
      } else if (totalCancelled === total) {
        color = 'red';
        statusLabel = 'Cancelled';
      } else if (totalPending === total) {
        color = 'orange';
        statusLabel = 'Pending';
      } else {
        color = 'blue';
        statusLabel = `${totalCompleted} ✅ / ${totalCancelled} ❌ / ${totalPending} ⏳`;
      }

      return {
        title: statusLabel,
        date,
        color
      };
    });

    res.render('Admin/dashboard', {
      employeeId: user.employeeId,
      firstName: user.firstname,
      lastName: user.lastname,
      calendarEvents: JSON.stringify(calendarEvents)
    });

  } catch (err) {
    console.error('Error fetching dashboard data:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/admin_user_management', isAuthenticated, async (req, res) => {
  try {
    const employees = await User.find({ role: { $ne: 'admin' } });
    res.render('Admin/user_management', { employees });
  } catch (err) {
    res.status(500).send('Failed to load user management view');
  }
});

app.post('/admin_update_user_status', isAuthenticated, async (req, res) => {
  const { employeeId, status } = req.body;

  try {
    const user = await User.findById(req.session.user.id);
    const targetEmployee = await User.findOneAndUpdate(
      { employeeId },
      { status },
      { new: true } // Return the updated doc
    );

    if (!targetEmployee) return res.status(404).send('User not found');

    await Log.create({
      action: 'Update Employee Status',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Changed status of employee ${targetEmployee.firstname} ${targetEmployee.lastname} (ID: ${employeeId}) to ${status}.`
    });

    res.status(200).send('Status updated');
  } catch (err) {
    console.error('Error updating user status:', err);
    res.status(500).send('Failed to update user status');
  }
});

app.post('/admin_update_user', isAuthenticated, async (req, res) => {
  const { employeeId, department, lastname, firstname, role, email } = req.body;

  try {
    const user = await User.findById(req.session.user.id);
    const updated = await User.findOneAndUpdate(
      { employeeId },
      { department, lastname, firstname, role, email },
      { new: true }
    );

    if (!updated) return res.status(404).send('Employee not found');

    await Log.create({
      action: 'Update Employee',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Updated employee: ${firstname} ${lastname} (ID: ${employeeId}), role: ${role}, department: ${department}.`
    });

    res.redirect('/admin_user_management');
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).send('Failed to update user');
  }
});

app.post('/admin_create_schedule', isAuthenticated, async (req, res) => {
  const {
    firstname,
    lastname,
    department,
    date,
    start_time,
    end_time,
    year_level,
    semester,
    subject_code,
    subject,
    observer,
    modality,
  } = req.body;

  const user = await User.findById(req.session.user.id);  

  try {
    const newSchedule = new Schedule({
      firstname,
      lastname,
      department,
      date,
      start_time,
      end_time,
      year_level,
      semester,
      subject_code,
      subject,
      observer,
      modality,
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date()
    });
  
    await newSchedule.save();
    
    await Log.create({
      action: 'Create Schedule',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Created a schedule for ${firstname} ${lastname} (Observer: ${observer}). Date : ${date}`
    });

    res.redirect('/admin_schedule');
  } catch {
    res.redirect('/admin_schedule');
  }
})

app.get('/admin_schedule', isAuthenticated, async (req, res) => {
    try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    const schedules = await Schedule.find().sort({ timestamp: -1 });
    console.log(schedules)
    res.render('Admin/schedule', { schedules, firstName : user.firstname, lastName : user.lastname, employeeId : user.employeeId });
  } catch (err) {
    console.error('Error fetching logs:', err); 
    res.status(500).send('Failed to load logs');
  }
});


// Cancel schedule
app.post('/admin/schedule/cancel/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'cancelled' });
  res.redirect('/admin_schedule');
});

// Complete schedule
app.post('/admin/schedule/complete/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'completed' });
  res.redirect('/admin_schedule');
});

// Approve schedule
app.post('/admin/schedule/approve/:id', isAuthenticated, async (req, res) => {
  await Schedule.findByIdAndUpdate(req.params.id, { status: 'approved' });
  res.redirect('/admin_schedule');
});

// Update schedule
app.post('/admin/schedule/update/:id', isAuthenticated, async (req, res) => {
  const { firstname, lastname, department, start_time, end_time, year_level, semester, subject, subject_code, observer, modality } = req.body;

  await Schedule.findByIdAndUpdate(req.params.id, {
    firstname,
    lastname,
    department,
    start_time,
    end_time,
    year_level,
    semester,
    subject,
    subject_code,
    observer,
    modality,
    updatedAt: new Date()
  });

  res.redirect('/super_admin_schedule');
});

app.get('/admin_copus_result',isAuthenticated, (req, res) => res.render('Admin/copus_result'));
app.get('/admin_copus_history',isAuthenticated, (req, res) => res.render('Admin/copus_history'));
app.get('/admin_setting',isAuthenticated, (req, res) => res.render('Admin/setting'));

// Super Admin Pages
// In app.js

app.get('/super_admin_dashboard', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        if (!user) return res.redirect('/login');

        // --- Fetching Metric Card Data ---

        // 1. Total Number of Observations (from the Schedule collection)
        // This should be the total count of all schedules, regardless of status.
        const totalObservations = await Schedule.countDocuments({});

        // 2. Total Number of Observers
        // Observers are typically users with a specific role, e.g., 'observer' or 'faculty'
        // Let's assume 'observer' role or 'faculty' role are the ones who can observe.
        // Adjust the role query as per your User model's 'role' field.
        const totalObservers = await User.countDocuments({ role: 'Observer' }); // Or { $or: [{ role: 'observer' }, { role: 'faculty' }] }

        // 3. Total Number of CIT Faculty
        // Assuming 'faculty' role and 'cit' department
        const totalCitFaculty = await User.countDocuments({ role: 'Faculty' });

        // --- Existing Calendar Event Logic ---
        const schedules = await Schedule.find({}); // Fetch all schedules for the calendar
        const eventMap = {};

        // Group schedules by date
        schedules.forEach(sch => {
            const date = new Date(sch.date).toISOString().split('T')[0];
            if (!eventMap[date]) eventMap[date] = [];
            eventMap[date].push(sch);
        });

        const calendarEvents = Object.entries(eventMap).map(([date, scheduleList]) => {
            const total = scheduleList.length;

            const totalCompleted = scheduleList.filter(s => s.status && s.status.toLowerCase() === 'completed').length;
            const totalCancelled = scheduleList.filter(s => s.status && s.status.toLowerCase() === 'cancelled').length;
            const totalPending = scheduleList.filter(s => s.status && s.status.toLowerCase() === 'pending').length;

            let color = 'orange'; // Default to pending
            let statusLabel = 'Pending';

            if (totalCompleted === total && total > 0) { // All are completed
                color = 'green';
                statusLabel = 'Completed';
            } else if (totalCancelled === total && total > 0) { // All are cancelled
                color = 'red';
                statusLabel = 'Cancelled';
            } else if (totalPending === total && total > 0) { // All are pending
                color = 'orange';
                statusLabel = 'Pending';
            } else if (totalCompleted > 0 || totalCancelled > 0 || totalPending > 0) {
                // Mixed statuses or some are pending
                color = 'blue'; // Or another color for mixed status
                statusLabel = `${totalCompleted} ✅ / ${totalCancelled} ❌ / ${totalPending} ⏳`;
            } else {
                 // No schedules for this date (though this case shouldn't be hit if eventMap is populated)
                 color = 'gray';
                 statusLabel = 'No Schedules';
            }


            return {
                title: statusLabel,
                start: date, // FullCalendar uses 'start' for all-day events
                color
            };
        });

        res.render('Super_Admin/dashboard', {
            employeeId: user.employeeId,
            firstName: user.firstname,
            lastName: user.lastname,
            totalObservations: totalObservations, // Pass to EJS
            totalObservers: totalObservers,     // Pass to EJS
            totalCitFaculty: totalCitFaculty,   // Pass to EJS
            calendarEvents: JSON.stringify(calendarEvents)
        });

    } catch (err) {
        console.error('Error fetching dashboard data:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Route for starting Copus 1 observation
app.get('/super_admin_copus_start_copus1/:scheduleId', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.params.scheduleId;

    const schedule = await Schedule.findById(scheduleId);

    if (!schedule) {
      return res.status(404).send('Schedule not found');
    }

    req.session.scheduleId = scheduleId; // Store scheduleId in session

    const copusDetails = {
      fullname: `${schedule.firstname} ${schedule.lastname}`,
      department: schedule.department,
      date: new Date(schedule.date).toLocaleDateString(),
      startTime: schedule.start_time,
      endTime: schedule.end_time,
      yearLevel: schedule.year_level,
      semester: schedule.semester,
      subjectCode: schedule.subject_code,
      subjectName: schedule.subject,
      mode: schedule.modality,
      observer: schedule.observer,
      copusType: schedule.copus
    };

    console.log(`Starting Copus 1 for schedule ID: ${scheduleId}`);

    // Render the view for Copus 1
    res.render('super_admin/copus_start', { // Corrected view name
      copusDetails,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (error) {
    console.error('Error fetching schedule for Copus 1:', error);
    res.status(500).send('Internal server error');
  }
});

// Route for starting Copus 2 observation
app.get('/super_admin_copus_start_copus2/:scheduleId', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.params.scheduleId;

    const schedule = await Schedule.findById(scheduleId);

    if (!schedule) {
      return res.status(404).send('Schedule not found');
    }

    req.session.scheduleId = scheduleId; // Store scheduleId in session

    const copusDetails = {
      fullname: `${schedule.firstname} ${schedule.lastname}`,
      department: schedule.department,
      date: new Date(schedule.date).toLocaleDateString(),
      startTime: schedule.start_time,
      endTime: schedule.end_time,
      yearLevel: schedule.year_level,
      semester: schedule.semester,
      subjectCode: schedule.subject_code,
      subjectName: schedule.subject,
      mode: schedule.modality,
      observer: schedule.observer,
      copusType: schedule.copus
    };

    console.log(`Starting Copus 2 for schedule ID: ${scheduleId}`);

    // Render the view for Copus 2
    res.render('super_admin/copus_start2', { // Corrected view name
      copusDetails,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (error) {
    console.error('Error fetching schedule for Copus 2:', error);
    res.status(500).send('Internal server error');
  }
});

// Route for starting Copus 3 observation
app.get('/super_admin_copus_start_copus3/:scheduleId', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.params.scheduleId;

    const schedule = await Schedule.findById(scheduleId);

    if (!schedule) {
      return res.status(404).send('Schedule not found');
    }

    req.session.scheduleId = scheduleId; // Store scheduleId in session

    const copusDetails = {
      fullname: `${schedule.firstname} ${schedule.lastname}`,
      department: schedule.department,
      date: new Date(schedule.date).toLocaleDateString(),
      startTime: schedule.start_time,
      endTime: schedule.end_time,
      yearLevel: schedule.year_level,
      semester: schedule.semester,
      subjectCode: schedule.subject_code,
      subjectName: schedule.subject,
      mode: schedule.modality,
      observer: schedule.observer,
      copusType: schedule.copus
    };

    console.log(`Starting Copus 3 for schedule ID: ${scheduleId}`);

    // Render the view for Copus 3
    res.render('super_admin/copus_start3', { // Corrected view name
      copusDetails,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (error) {
    console.error('Error fetching schedule for Copus 3:', error);
    res.status(500).send('Internal server error');
  }
});

// --- Save Observation Data Routes ---

// Display Copus 1 result
app.get('/super_admin_copus_result1/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 1,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 1 observation found for this schedule.');
    }

    // You might also want to fetch the schedule details here to display on the result page
    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    const tallies = {
      studentActions: Object.fromEntries(copusObservation.studentActions || new Map()),
      teacherActions: Object.fromEntries(copusObservation.teacherActions || new Map()),
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    const copusDetails = {
      copusType: `Copus ${copusObservation.copusNumber}`
    };

    res.render('super_admin/copus_result1', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleId: scheduleId,
      copusDetails: copusDetails,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving Copus 1 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Display Copus 2 result
app.get('/super_admin_copus_result2/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 2,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 2 observation found for this schedule.');
    }

    // Fetch schedule details for the view
    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    const tallies = {
      studentActions: copusObservation.studentActions || {},
      teacherActions: copusObservation.teacherActions || {},
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    res.render('super_admin/copus_result2', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving Copus 2 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Display aggregated Copus 3 result (for all 3 Copus observations for a schedule)
app.get('/super_admin_copus_result3/:scheduleId', isAuthenticated, async (req, res) => { // ADDED :scheduleId
  try {
    const scheduleId = req.params.scheduleId; // Get scheduleId from URL parameter
    if (!scheduleId) {
      return res.status(400).send('Schedule ID is missing from URL.');
    }

    const scheduleDetails = await Schedule.findById(scheduleId);
    if (!scheduleDetails) {
        return res.status(404).send('Schedule details not found.');
    }

    // Fetch all COPUS observations for the same schedule and observer
    const copusObservations = await CopusObservation.find({
      scheduleId: scheduleId,
      observerId: req.session.user.id
    }).exec();

    if (copusObservations.length === 0) {
      return res.status(404).send('No observations found for this schedule.');
    }

    const aggregatedTallies = {
      studentActions: {},
      teacherActions: {},
      engagementLevels: { High: 0, Med: 0, Low: 0 },
      totalIntervals: 0
    };

    copusObservations.forEach(obs => {
      for (const [action, count] of Object.entries(obs.studentActions || {})) {
        aggregatedTallies.studentActions[action] = (aggregatedTallies.studentActions[action] || 0) + count;
      }

      for (const [action, count] of Object.entries(obs.teacherActions || {})) {
        aggregatedTallies.teacherActions[action] = (aggregatedTallies.teacherActions[action] || 0) + count;
      }

      for (const level of ['High', 'Med', 'Low']) {
        aggregatedTallies.engagementLevels[level] += obs.engagementLevels?.[level] || 0;
      }

      aggregatedTallies.totalIntervals += Object.values(obs.studentActions || {}).reduce((a, b) => a + b, 0);
    });

    const engagementPercentages = {
      High: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.High / aggregatedTallies.totalIntervals) * 100 : 0,
      Med: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Med / aggregatedTallies.totalIntervals) * 100 : 0,
      Low: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Low / aggregatedTallies.totalIntervals) * 100 : 0
    };

    res.render('super_admin/copus_result3', {
      tallies: aggregatedTallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleDetails: scheduleDetails // Pass schedule details
    });
  } catch (err) {
    console.error('Error retrieving aggregated COPUS observations:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Saving the first copus observation and redirect to its result
// Inside your app.post('/observer_copus_result1', ...) route:
app.post('/super_admin_copus_result1', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId;
    const copusNumber = 1;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

 
    // Alternatively, you can just do:
    const collectedComments = rows.map(row => row.comment).filter(Boolean).join(' ') || 'No comments provided.';


    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: collectedComments, // Use the prepared comments string
      observerId: user.id
    });

    await copusObservation.save();

    res.redirect(`/super_admin_copus_result1`);
  } catch (err) {
    console.error('Error saving COPUS 1 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Save copus 2 observation and redirect to its result
app.post('/super_admin_copus_result2', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId; // Retrieve scheduleId from session
    const copusNumber = 2;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: rows.map(row => row.comment).filter(Boolean).join(' '),
      observerId: user.id
    });

    await copusObservation.save();

    // Redirect to the GET route that displays Copus 2 results
    res.redirect(`/super_admin_copus_result2`); // Redirect to a new GET route for Copus 2 results
  } catch (err) {
    console.error('Error saving COPUS 2 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Save copus 3 observation and mark the schedule as done, then redirect to aggregated result
app.post('/super_admin_copus_result3', isAuthenticated, async (req, res) => {
  try {
    const { rows } = req.body;
    const user = req.session.user;
    const scheduleId = req.session.scheduleId; // Retrieve scheduleId from session
    const copusNumber = 3;

    if (!scheduleId) {
      return res.status(400).send('Schedule ID not found in session. Please start an observation first.');
    }

    // Mark the schedule as completed
    const markSched = await Schedule.findById(scheduleId);
    if (markSched) {
      markSched.status = "completed";
      await markSched.save();
    } else {
      console.warn('Schedule not found when trying to mark as completed:', scheduleId);
    }

    const copusObservation = new CopusObservation({
      scheduleId,
      copusNumber,
      studentActions: rows.reduce((acc, row) => {
        for (const action in row.student) {
          acc[action] = (acc[action] || 0) + row.student[action];
        }
        return acc;
      }, {}),
      teacherActions: rows.reduce((acc, row) => {
        for (const action in row.teacher) {
          acc[action] = (acc[action] || 0) + row.teacher[action];
        }
        return acc;
      }, {}),
      engagementLevels: {
        High: rows.reduce((acc, row) => acc + (row.engagement?.High || 0), 0),
        Med: rows.reduce((acc, row) => acc + (row.engagement?.Med || 0), 0),
        Low: rows.reduce((acc, row) => acc + (row.engagement?.Low || 0), 0),
      },
      comments: rows.map(row => row.comment).filter(Boolean).join(' '),
      observerId: user.id
    });

    await copusObservation.save();

    // Redirect to the GET route that displays aggregated Copus results
    res.redirect(`/super_admin_copus_result3`);
  } catch (err) {
    console.error('Error saving COPUS 3 observation:', err);
    res.status(500).send('Internal Server Error');
  }
});

// --- Display Observation Results Routes ---

// Display Copus 1 result
// Inside your app.get('/observer_copus_result1', ...) route:
app.get('/super_admin_copus_result1', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId;
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 1,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 1 observation found for this schedule.');
    }


    const tallies = {
      // Convert Map to plain object using Object.fromEntries()
      studentActions: Object.fromEntries(copusObservation.studentActions || new Map()),
      teacherActions: Object.fromEntries(copusObservation.teacherActions || new Map()),
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    // Calculate total intervals based on the sum of all student action counts
    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    const copusDetails = {
    copusType: `Copus ${copusObservation.copusNumber}` // This assumes copusObservation.copusNumber exists (which it should if copusObservation is found)
};

console.log('Copus 1 Tallies:', tallies);
console.log('Engagement Percentages:', engagementPercentages);
console.log('Copus Details:', copusDetails); // Add this log!

    res.render('super_admin/copus_result1', {
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId,
      scheduleId: scheduleId,
      copusDetails: copusDetails
    });
  } catch (err) {
    console.error('Error retrieving Copus 1 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});

// IMPORTANT: Apply the same Object.fromEntries() conversion
// to your /observer_copus_result2 and /observer_copus_result3 GET routes as well!

// New: Display Copus 2 result
app.get('/super_admin_copus_result2', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId; // Get scheduleId from session
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    // Get the latest observation for the current schedule and Copus 2
    const copusObservation = await CopusObservation.findOne({
      scheduleId: scheduleId,
      copusNumber: 2,
      observerId: req.session.user.id
    }).sort({ dateSubmitted: -1 }).exec();

    if (!copusObservation) {
      return res.status(404).send('No Copus 2 observation found for this schedule.');
    }

    const tallies = {
      studentActions: copusObservation.studentActions || {},
      teacherActions: copusObservation.teacherActions || {},
      engagementLevels: copusObservation.engagementLevels || { High: 0, Med: 0, Low: 0 },
    };

    const totalIntervals = Object.values(tallies.studentActions).reduce((sum, count) => sum + count, 0);

    const engagementPercentages = {
      High: totalIntervals > 0 ? (tallies.engagementLevels.High / totalIntervals) * 100 : 0,
      Med: totalIntervals > 0 ? (tallies.engagementLevels.Med / totalIntervals) * 100 : 0,
      Low: totalIntervals > 0 ? (tallies.engagementLevels.Low / totalIntervals) * 100 : 0
    };

    console.log('Copus 2 Tallies:', tallies);

    // Render the result page for Copus 2
    res.render('super_admin/copus_result2', { // You'll need to create this EJS file
      tallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (err) {
    console.error('Error retrieving Copus 2 observation results:', err);
    res.status(500).send('Internal Server Error');
  }
});


// Display aggregated Copus 3 result (for all 3 Copus observations for a schedule)
app.get('/super_admin_copus_result3', isAuthenticated, async (req, res) => {
  try {
    const scheduleId = req.session.scheduleId; // Get scheduleId from session
    if (!scheduleId) {
      return res.status(400).send('No active schedule found in session.');
    }

    // Fetch all COPUS observations for the same schedule and observer
    const copusObservations = await CopusObservation.find({
      scheduleId: scheduleId,
      observerId: req.session.user.id
    }).exec();

    if (copusObservations.length === 0) {
      return res.status(404).send('No observations found for this schedule.');
    }

    const aggregatedTallies = {
      studentActions: {},
      teacherActions: {},
      engagementLevels: { High: 0, Med: 0, Low: 0 },
      totalIntervals: 0
    };

    copusObservations.forEach(obs => {
      for (const [action, count] of Object.entries(obs.studentActions || {})) {
        aggregatedTallies.studentActions[action] = (aggregatedTallies.studentActions[action] || 0) + count;
      }

      for (const [action, count] of Object.entries(obs.teacherActions || {})) {
        aggregatedTallies.teacherActions[action] = (aggregatedTallies.teacherActions[action] || 0) + count;
      }

      for (const level of ['High', 'Med', 'Low']) {
        aggregatedTallies.engagementLevels[level] += obs.engagementLevels?.[level] || 0;
      }

      // Summing up all counts in studentActions to get totalIntervals
      aggregatedTallies.totalIntervals += Object.values(obs.studentActions || {}).reduce((a, b) => a + b, 0);
    });

    // Recalculate percentages based on the aggregated total intervals
    const engagementPercentages = {
      High: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.High / aggregatedTallies.totalIntervals) * 100 : 0,
      Med: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Med / aggregatedTallies.totalIntervals) * 100 : 0,
      Low: aggregatedTallies.totalIntervals > 0 ? (aggregatedTallies.engagementLevels.Low / aggregatedTallies.totalIntervals) * 100 : 0
    };

    res.render('super_admin/copus_result3', { // You'll need to create this EJS file
      tallies: aggregatedTallies,
      engagementPercentages,
      firstName: req.session.user.firstname,
      lastName: req.session.user.lastname,
      employeeId: req.session.user.employeeId
    });
  } catch (err) {
    console.error('Error retrieving aggregated COPUS observations:', err);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/super_admin_user_management', isAuthenticated, async (req, res) => {
  try {
    // Fetch the current authenticated user's information
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login'); // Redirect if user somehow isn't found
    }

    const employees = await User.find({ role: { $ne: 'super_admin' } });

    res.render('Super_Admin/user_management', {
      employees,
      firstName: user.firstname, // Pass firstName
      lastName: user.lastname,   // Pass lastName
      employeeId: user.employeeId // Pass employeeId
    });
  } catch (err) {
    console.error('Error fetching user management data:', err); // Log the error for debugging
    res.status(500).send('Failed to load user management view');
  }
});


// fix the front end add create the form for updating the user status also send an email once the process is success
app.post('/update_user_status', isAuthenticated, async (req, res) => {
  const { employeeId, status } = req.body;

  try {
    const user = await User.findById(req.session.user.id);
    const targetEmployee = await User.findOneAndUpdate(
      { employeeId },
      { status },
      { new: true } // Return the updated doc
    );

    if (!targetEmployee) return res.status(404).send('User not found');

    await Log.create({
      action: 'Update Employee Status',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Changed status of employee ${targetEmployee.firstname} ${targetEmployee.lastname} (ID: ${employeeId}) to ${status}.`
    });

    res.status(200).send('Status updated');
  } catch (err) {
    console.error('Error updating user status:', err);
    res.status(500).send('Failed to update user status');
  }
});

// fix the front enf for this and test the backend and send an email tot he user once the proccess is a success
app.post('/update_user', isAuthenticated, async (req, res) => {
  const { employeeId, department, lastname, firstname, role, email } = req.body;

  try {
    const user = await User.findById(req.session.user.id);
    const updated = await User.findOneAndUpdate(
      { employeeId },
      { department, lastname, firstname, role, email },
      { new: true }
    );

    if (!updated) return res.status(404).send('Employee not found');

    await Log.create({
      action: 'Update Employee',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Updated employee: ${firstname} ${lastname} (ID: ${employeeId}), role: ${role}, department: ${department}.`
    });

    res.redirect('/super_admin_user_management');
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).send('Failed to update user');
  }
});


// Find the observer and the one getting observed and send an email to them for notification
app.post('/create_schedule', isAuthenticated, async (req, res) => {
  const {
    firstname,
    lastname,
    department,
    date,
    start_time,
    end_time,
    year_level,
    semester,
    subject_code,
    subject,
    observer,
    modality,
  } = req.body;

  const user = await User.findById(req.session.user.id);  

  try {
    const newSchedule = new Schedule({
      firstname,
      lastname,
      department,
      date,
      start_time,
      end_time,
      year_level,
      semester,
      subject_code,
      subject,
      observer,
      modality,
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date()
    });
  
    await newSchedule.save();
    
    await Log.create({
      action: 'Create Schedule',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Created a schedule for ${firstname} ${lastname} (Observer: ${observer}). Date : ${date}`
    });

    res.redirect('/super_admin_schedule');
  } catch {
    res.redirect('/super_admin_schedule');
  }
})

app.get('/super_admin_schedule', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        if (!user) {
            return res.redirect('/login');
        }

        // Fetch all schedules
        const schedules = await Schedule.find().sort({ date: -1, start_time: 1 }); // Sort by date then start time

        // Fetch all users who can be observers (role: 'Observer' or 'super_admin')
        const observers = await User.find({ $or: [{ role: 'Observer' }, { role: 'super_admin' }] });

        res.render('Super_Admin/schedule', {
            schedules,
            observers, // Pass observers to the EJS template
            firstName: user.firstname,
            lastName: user.lastname,
            employeeId: user.employeeId
        });
    } catch (err) {
        console.error('Error fetching schedules or user data:', err);
        res.status(500).send('Failed to load schedules');
    }
});

//  In this part the date is not being updated in the database fix it if may time
// Cancel schedule
// ROUTE: POST /schedule/cancel/:id
app.post('/schedule/cancel/:id', isAuthenticated, async (req, res) => {
    try {
        const schedule = await Schedule.findById(req.params.id);
        if (!schedule) {
            return res.status(404).send('Schedule not found.');
        }

        const user = await User.findById(req.session.user.id);
        if (!user) return res.redirect('/login');

        if (schedule.status === 'pending') {
            await Schedule.findByIdAndUpdate(req.params.id, { status: 'cancelled' });
            await Log.create({
                action: 'Cancel Schedule',
                performedBy: user.id,
                performedByRole: user.role,
                details: `Super Admin cancelled schedule for ${schedule.firstname} ${schedule.lastname} (Observer: ${schedule.observer}). Date: ${schedule.date.toISOString().split('T')[0]}`
            });
        }
        res.redirect('/super_admin_schedule');
    } catch (error) {
        console.error('Error cancelling schedule:', error);
        res.status(500).send('Failed to cancel schedule.');
    }
});

// Complete schedule
// ROUTE: POST /schedule/complete/:id
app.post('/schedule/complete/:id', isAuthenticated, async (req, res) => {
    try {
        const schedule = await Schedule.findById(req.params.id);
        if (!schedule) {
            return res.status(404).send('Schedule not found.');
        }

        const user = await User.findById(req.session.user.id);
        if (!user) return res.redirect('/login');

        if (schedule.status === 'pending' || schedule.status === 'approved') { // Only complete if pending or approved
            await Schedule.findByIdAndUpdate(req.params.id, { status: 'completed' });
            await Log.create({
                action: 'Complete Schedule',
                performedBy: user.id,
                performedByRole: user.role,
                details: `Super Admin marked schedule as completed for ${schedule.firstname} ${schedule.lastname} (Observer: ${schedule.observer}). Date: ${schedule.date.toISOString().split('T')[0]}`
            });
        }
        res.redirect('/super_admin_schedule');
    } catch (error) {
        console.error('Error completing schedule:', error);
        res.status(500).send('Failed to complete schedule.');
    }
});

app.post('/schedule/approve/:id', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.user.id);
        // Ensure only Super Admin can approve
        if (!user || user.role !== 'super_admin') {
            return res.status(403).send('Access Denied: Only Super Admin can approve schedules.');
        }

        const schedule = await Schedule.findById(req.params.id);
        if (!schedule) {
            return res.status(404).send('Schedule not found.');
        }

        // Only approve if the current status is 'pending'
        if (schedule.status === 'pending') {
            await Schedule.findByIdAndUpdate(req.params.id, { status: 'approved' });
            await Log.create({
                action: 'Approve Schedule',
                performedBy: user.id,
                performedByRole: user.role,
                details: `Super Admin approved schedule for ${schedule.firstname} ${schedule.lastname} (Observer: ${schedule.observer}). Date: ${schedule.date.toISOString().split('T')[0]}`
            });
        }
        res.redirect('/super_admin_schedule');
    } catch (error) {
        console.error('Error approving schedule:', error);
        res.status(500).send('Failed to approve schedule.');
    }
});


// Update schedule
// ROUTE: POST /schedule/update/:id
app.post('/schedule/update/:id', isAuthenticated, async (req, res) => {
    const { firstname, lastname, department, date, start_time, end_time, year_level, semester, subject, subject_code, observer, modality, copus } = req.body; // Added copus

    try {
        const user = await User.findById(req.session.user.id);
        if (!user) return res.redirect('/login');

        const existingSchedule = await Schedule.findById(req.params.id);
        if (!existingSchedule) {
            return res.status(404).send('Schedule not found.');
        }

        // Convert times to Date objects for overlap check
        const updatedStart = parseDateTime(date, start_time);
        const updatedEnd = parseDateTime(date, end_time);

        // Check for overlapping APPROVED schedules for the selected observer
        const conflictingSchedule = await Schedule.findOne({
            _id: { $ne: req.params.id }, // Exclude the current schedule being updated
            observer: observer,
            date: new Date(date), // Ensure date is treated as a Date object for comparison
            status: 'approved',
            $or: [
                {
                    start_time: { $lt: end_time }, // New start is before existing end
                    end_time: { $gt: start_time }  // New end is after existing start
                },
                // Additional check for cases where start_time and end_time might be strings and comparisons need full Date objects
                {
                    $and: [
                        { $expr: { $lt: [ { $dateFromString: { dateString: { $concat: [ { $dateToString: { format: "%Y-%m-%d", date: "$date" } }, "T", "$end_time" ] } } }, updatedStart ] } },
                        { $expr: { $gt: [ { $dateFromString: { dateString: { $concat: [ { $dateToString: { format: "%Y-%m-%d", date: "$date" } }, "T", "$start_time" ] } } }, updatedEnd ] } }
                    ]
                }
            ]
        });


        // Fallback for more robust time parsing and comparison
        if (conflictingSchedule) {
            const conflictStart = parseDateTime(conflictingSchedule.date.toISOString().split('T')[0], conflictingSchedule.start_time);
            const conflictEnd = parseDateTime(conflictingSchedule.date.toISOString().split('T')[0], conflictingSchedule.end_time);

            if (updatedStart < conflictEnd && updatedEnd > conflictStart) {
                // If there's an actual time overlap, send error message
                const schedules = await Schedule.find().sort({ timestamp: -1 });
                const observers = await User.find({ $or: [{ role: 'Observer' }, { role: 'super_admin' }] });
                return res.render('Super_Admin/schedule', {
                    schedules,
                    observers,
                    firstName: user.firstname,
                    lastName: user.lastname,
                    employeeId: user.employeeId,
                    errorMessage: 'The selected observer already has an approved appointment that overlaps with the updated time.'
                });
            }
        }

        await Schedule.findByIdAndUpdate(req.params.id, {
            firstname,
            lastname,
            department,
            date: new Date(date), // Ensure date is stored as Date object
            start_time,
            end_time,
            year_level,
            semester,
            subject,
            subject_code,
            observer,
            modality,
            copus, // Make sure copus is included here
            updatedAt: new Date()
        });

        await Log.create({
            action: 'Update Schedule',
            performedBy: user.id,
            performedByRole: user.role,
            details: `Super Admin updated schedule for ${firstname} ${lastname} (ID: ${req.params.id}). Observer: ${observer}. Date: ${date}`
        });

        res.redirect('/super_admin_schedule');
    } catch (err) {
        console.error('Error updating schedule:', err);
        res.status(500).send('Failed to update schedule.');
    }
});

app.get('/super_admin_copus_result', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    // Fetch all schedules where the observer matches and status is 'completed'
    // Select all fields you need for display
    const completedSchedules = await Schedule.find({
      observer: user.firstname + " " + user.lastname,
      status: 'completed'
    }).sort({ date: -1, start_time: -1 })
      .select('firstname lastname department date start_time end_time year_level semester subject_code subject observer copus modality');

    res.render('Super_Admin/copus_result', {
      completedSchedules: completedSchedules,
      firstName: user.firstname,
      lastName: user.lastname,
      employeeId: user.employeeId
    });
  } catch (err) {
    console.error('Error fetching completed schedules for Copus Result:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/super_admin_copus_history', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login');
    }

    const observerFullName = `${user.firstname} ${user.lastname}`;

    // Fetch schedules that are completed and where the observer matches the logged-in user
    const completedSchedules = await Schedule.find({
      observer: observerFullName,
      status: 'completed' // Filter for completed schedules
    }).sort({ date: -1, start_time: -1 }); // Sort by most recent date, then start time

    res.render('Super_Admin/copus_history', {
      completedSchedules: completedSchedules,
      firstName: user.firstname,
      lastName: user.lastname,
      employeeId: user.employeeId
    });
  } catch (err) {
    console.error('Error fetching completed COPUS history:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/super_admin_copus', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.user.id);
    if (!user) return res.redirect('/login');

    // Fetch all the necessary fields from the schedules where the observer matches and status is 'approved'
    const schedules = await Schedule.find(
      { observer: user.firstname + " " + user.lastname, status: 'approved' }
    )
    .select('firstname lastname department date start_time end_time year_level semester subject_code subject observer copus modality ');

    res.render('Super_Admin/copus', {
      schedules: schedules, // Pass schedules to the view
      firstName: user.firstname,
      lastName: user.lastname,
      employeeId: user.employeeId
    });
  } catch (err) {
    console.error('Error fetching approved schedules:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/super_admin_setting', isAuthenticated, async (req, res) => {
  try {
    // Fetch the current authenticated user's information
    const user = await User.findById(req.session.user.id);
    if (!user) {
      return res.redirect('/login'); // Redirect if user somehow isn't found
    }

    res.render('Super_Admin/setting', {
      firstName: user.firstname,         // For sidebar/header
      lastName: user.lastname,          // For sidebar/header
      employeeId: user.employeeId,      // For sidebar
      currentUser: user                 // Pass the full user object for the form details
    });
  } catch (err) {
    console.error('Error fetching user data for settings page:', err); // Corrected log message
    res.status(500).send('Failed to load Settings view'); // Corrected error message
  }
});

app.post('/super_admin_update_profile', isAuthenticated, async (req, res) => {
    const userId = req.session.user.id;

    // Define the fields that are allowed to be updated from the form
    // Ensure these fields exist in your User schema
    const allowedUpdates = [
        'firstname', 'lastname', 'middleInitial', 'email', 'department', 'dean',
        'assignedProgramHead', 'yearsOfTeachingExperience', 'yearHired',
        'yearRegularized', 'highestEducationalAttainment', 'professionalLicense',
        'employmentStatus', 'rank'
    ];

    const updates = {};
    for (const key of allowedUpdates) {
        if (req.body[key] !== undefined) { // Check if key exists and is not undefined
            updates[key] = req.body[key];
        } else if (req.body[key] === undefined && (key === 'middleInitial' || key === 'assignedProgramHead')) {
            // Allow specific optional fields to be cleared if sent as undefined, by setting them to empty string or null
            // Or handle this based on your schema (e.g. if empty string is preferred over null)
            updates[key] = ''; // Or null, depending on schema
        }
    }
    
    // Basic validation example for email (add more as needed)
    if (updates.email && !/\S+@\S+\.\S+/.test(updates.email)) {
        return res.status(400).json({ message: 'Invalid email format.' });
    }
    // You might want to check if primary email is changing to one that already exists for another user

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ message: 'No update data provided.' });
    }

    try {
        const oldUser = await User.findById(userId).lean(); // .lean() for plain JS object for comparison

        const updatedUser = await User.findByIdAndUpdate(userId, { $set: updates }, { new: true, runValidators: true });

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Update session data for consistency in the UI
        req.session.user.firstname = updatedUser.firstname;
        req.session.user.lastname = updatedUser.lastname;
        req.session.user.email = updatedUser.email;
        // Add any other fields to session if they are critical for immediate UI display
        await req.session.save();

        // Construct details for logging changes
        let logDetails = 'Super Admin updated own profile. Changes: ';
        const changedFieldsArray = [];
        for (const key in updates) {
            if (oldUser && String(oldUser[key]) !== String(updatedUser[key])) {
                changedFieldsArray.push(`${key} (from '${oldUser[key] || ''}' to '${updatedUser[key] || ''}')`);
            } else if (!oldUser && updatedUser[key]) { // Field was added
                 changedFieldsArray.push(`${key} (set to '${updatedUser[key] || ''}')`);
            }
        }
        logDetails += changedFieldsArray.length > 0 ? changedFieldsArray.join(', ') : 'No values changed effectively.';

        await Log.create({
            action: 'Update Own Profile',
            performedBy: userId,
            performedByRole: updatedUser.role,
            details: logDetails
        });

        res.status(200).json({ 
            message: 'Profile updated successfully!',
            user: { // Send back some essential updated info if client needs it
                firstname: updatedUser.firstname,
                lastname: updatedUser.lastname,
                email: updatedUser.email
            }
        });

    } catch (error) {
        console.error('Error updating own user profile:', error);
        if (error.name === 'ValidationError') {
            // Extracting a more user-friendly message from Mongoose validation error
            const messages = Object.values(error.errors).map(e => e.message);
            return res.status(400).json({ message: 'Validation Error: ' + messages.join(', ') });
        }
        // Check for unique constraint errors, e.g., if email must be unique
        if (error.code === 11000) { // MongoDB duplicate key error
             return res.status(400).json({ message: 'Update failed. Email or another unique field may already be in use.' });
        }
        res.status(500).json({ message: 'Failed to update profile due to a server error.' });
    }
});

app.get('/super_admin_logs', isAuthenticated, async (req, res) => {
  try {
    const logs = await Log.find().sort({ timestamp: -1 });
    res.render('Super_Admin/logs', { logs });
  } catch (err) {
    console.error('Error fetching logs:', err);
    res.status(500).send('Failed to load logs');
  }
});

// Add Employee (Super Admin)
app.post('/add_employee', isAuthenticated, async (req, res) => {
  const {
    department,
    lastname,
    firstname,
    role,
    email,
  } = req.body;

  // Check if email ends with '@phinmaed.com'
  // if (!email.endsWith('@phinmaed.com')) {
    // return res.status(400).json({ error: 'Only PHINMA emails (@phinmaed.com) are allowed.' });
  // }

  // if the panel want to have the user different suername based on the role

  // let employeeId;
  
  // if(role == 'Faculty') {

  //   // generate random ID for the employee ID

  //   const randomPart1 = Math.floor(1000 + Math.random() * 9000); // 4-digit number
  //   const randomPart2 = Math.floor(1000 + Math.random() * 9000); // 4-digit number
  //   const employeeId = `TCH-${randomPart1}-${randomPart2}`;
  // } else if(role == 'Observer') {

  //   // generate random ID for the employee ID

  //   const randomPart1 = Math.floor(1000 + Math.random() * 9000); // 4-digit number
  //   const randomPart2 = Math.floor(1000 + Math.random() * 9000); // 4-digit number
  //   const employeeId = `OSV-${randomPart1}-${randomPart2}`;
  // } else {
  //   res.redirect('/super_admin_user_management');
  // }

  // generate random ID for the employee
  const randomPart1 = Math.floor(1000 + Math.random() * 9000); // 4-digit number
  const randomPart2 = Math.floor(1000 + Math.random() * 9000); // 4-digit number
  const employeeId = `EMP-${randomPart1}-${randomPart2}`;
  
  const password = employeeId;
  const user = await User.findById(req.session.user.id);

  console.log(user);

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { employeeId }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email or employee ID already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      employeeId,
      department,
      lastname,
      firstname,
      role,
      email,
      password: hashedPassword
    });

    await newUser.save();

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'copus6251@gmail.com',
        pass: 'spgh zwvd qevg oxoe '
      }
    });

    const mailOptions = {
      from: '"Admin" <copus6251@gmail.com>',
      to: email,
      subject: 'Your Login Credentials - PHINMA Copus System',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 8px; border: 1px solid #ddd;">
          <h2 style="color: #2c3e50;">Hello ${firstname} ${lastname},</h2>
          <p style="font-size: 15px; color: #333;">You have been added to the <strong>PHINMA Copus System</strong>. Here are your login credentials:</p>
          
          <div style="margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 8px; font-weight: bold;">Email:</td>
                <td style="padding: 8px;">${email}</td>
              </tr>
              <tr>
                <td style="padding: 8px; font-weight: bold;">Role:</td>
                <td style="padding: 8px;">${role}</td>
              </tr>
              <tr>
                <td style="padding: 8px; font-weight: bold;">Username:</td>
                <td style="padding: 8px;">${employeeId}</td>
              </tr>
              <tr>
                <td style="padding: 8px; font-weight: bold;">Password:</td>
                <td style="padding: 8px;">${password}</td>
              </tr>
            </table>
          </div>
    
          <p style="font-size: 15px; color: #333;">Please log in and change your password upon first login for security reasons.</p>
          
          <p style="margin-top: 30px; font-size: 14px; color: #555;">Best regards,<br><strong>PHINMA IT Team</strong></p>
        </div>
      `
    };
    

    await transporter.sendMail(mailOptions);

    // Add this to the logs page or create a log page
    await Log.create({
      action: 'Add Employee',
      performedBy: user.id,
      performedByRole: user.role,
      details: `Added an employee name : ${firstname} ${lastname} emplyoyee ID : (${employeeId}) with role ${role} in ${department}.`
    });

    res.redirect('/super_admin_user_management');

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add user or send email.' });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).send('404 - Page not found');
});

// Start Server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

// Middleware
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    return res.redirect('/login');
  }
}


