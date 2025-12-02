//npm install dotenv - explain
//npm install express-session - explain
//create the .env file

// Load environment variables from .env file into memory
// Allows you to use process.env
require('dotenv').config();

const express = require("express");

//Needed for the session variable - Stored on the server to hold data
const session = require("express-session");

let path = require("path");

const multer = require("multer");

// Allows you to read the body of incoming HTTP requests and makes that data available on req.body
let bodyParser = require("body-parser");

let app = express();

// Use EJS for the web pages - requires a views folder and all files are .ejs
app.set("view engine", "ejs");

// Root directory for static images
const uploadRoot = path.join(__dirname, "images");

// Sub-directory where uploaded profile pictures will be stored
const uploadDir = path.join(uploadRoot, "uploads");

// cb is the callback function
// The callback is how you hand control back to Multer after 
// your customization step

// Configure Multer's disk storage engine
// Multer calls it once per upload to ask where to store the file. Your function receives:
// req: the incoming request.
// file: metadata about the file (original name, mimetype, etc.).
// cb: the callback.
const storage = multer.diskStorage({
    // Save files into our uploads directory
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    // Reuse the original filename so users see familiar names
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});

// Create the Multer instance that will handle single-file uploads
const upload = multer({ storage });

// Expose everything in /images (including uploads) as static assets
app.use("/images", express.static(uploadRoot));

// Parse JSON bodies (as sent by API clients)
app.use(express.json());

// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: true }));

// process.env.PORT is when you deploy and 3001 is for test (3000 is often in use)
const port = process.env.PORT || 3001;

/* Session middleware (Middleware is code that runs between the time the request comes
to the server and the time the response is sent back. It allows you to intercept and
decide if the request should continue. It also allows you to parse the body request
from the html form, handle errors, check authentication, etc.)

REQUIRED parameters for session:
secret - The only truly required parameter
    Used to sign session cookies
    Prevents tampering and session hijacking with session data

OPTIONAL (with defaults):
resave - Default: true
    true = save session on every request
    false = only save if modified (recommended)

saveUninitialized - Default: true
    true = create session for every request
    false = only create when data is stored (recommended)
*/

app.use(
    session(
        {
            secret: process.env.SESSION_SECRET || 'fallback-secret-key',
            resave: false,
            saveUninitialized: false,
        }
    )
);

// Content Security Policy middleware - allows localhost connections for development
// This fixes the CSP violation error with Chrome DevTools
app.use((req, res, next) => {
    // Set a permissive CSP for development that allows localhost connections
    // This allows Chrome DevTools to connect to localhost:3000
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self' http://localhost:* ws://localhost:* wss://localhost:*; " +
        "connect-src 'self' http://localhost:* ws://localhost:* wss://localhost:*; " +
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "img-src 'self' data: https:; " +
        "font-src 'self' https://cdn.jsdelivr.net;"
    );
    next();
});

const knex = require("knex")({
    client: "pg",
    connection: {
        host: process.env.RDS_HOSTNAME || "awseb-e-qzuktehy2v-stack-awsebrdsdatabase-kjohppsz4ibe.cb8eie2ew4fz.us-east-2.rds.amazonaws.com",
        user: process.env.RDS_USERNAME || "intex2025",
        password: process.env.RDS_PASSWORD || "intex0403",
        database: process.env.RDS_DB_NAME || "ebdb",
        port: process.env.RDS_PORT || 5432,
        // Enable SSL for remote connections (required by pg_hba.conf)
        // If DB_SSL is explicitly set to false, disable SSL, otherwise enable it for remote hosts
        ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
    }
});

// Tells Express how to read form data sent in the body of a request
app.use(express.urlencoded({ extended: true }));

// Helper function to get user info with participant data
async function getUserInfo(req) {
    if (!req.session.isLoggedIn) {
        return null;
    }
    
    const userInfo = {
        username: req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U',
        participantid: req.session.participantid || null
    };
    
    // If user has a participantid, get participant data
    if (req.session.participantid) {
        try {
            const participant = await knex('participants')
                .where('participantid', req.session.participantid)
                .first();
            
            if (participant) {
                userInfo.first_name = participant.participantfirstname || '';
                userInfo.last_name = participant.participantlastname || '';
                userInfo.full_name = `${participant.participantfirstname || ''} ${participant.participantlastname || ''}`.trim() || req.session.username;
            } else {
                userInfo.first_name = '';
                userInfo.last_name = '';
                userInfo.full_name = req.session.username;
            }
        } catch (err) {
            console.error("Error fetching participant data:", err);
            userInfo.first_name = '';
            userInfo.last_name = '';
            userInfo.full_name = req.session.username;
        }
    } else {
        userInfo.first_name = '';
        userInfo.last_name = '';
        userInfo.full_name = req.session.username;
    }
    
    return userInfo;
}

// Global authentication middleware - runs on EVERY request
app.use((req, res, next) => {
    // Skip authentication for login routes, signup, events, and survey
    // Note: /events/add, /events/edit/:id, /events/delete/:id, /participants/add, /participants/edit/:id, /participants/delete/:id require manager authentication (checked in route handlers)
    if (req.path === '/' || req.path === '/login' || req.path === '/logout' || req.path === '/signup' || req.path === '/events' || req.path.startsWith('/events/') || req.path === '/rsvp' || req.path === '/survey' || req.path === '/surveys' || req.path === '/participants' || req.path.startsWith('/participants/') || req.path === '/milestones' || req.path === '/personal-milestones' || req.path === '/dashboard' || req.path === '/teapot' || req.path.startsWith('/api/')) {
        //continue with the request path
        return next();
    }

    // My Journey requires authentication
    if (req.path === '/my-journey') {
        if (req.session.isLoggedIn) {
            return next();
        } else {
            return res.render("login", { error_message: "Please log in to access this page" });
        }
    }

    // Check if user is logged in for all other routes
    if (req.session.isLoggedIn) {
        //notice no return because nothing below it
        next(); // User is logged in, continue
    }
    else {
        res.render("login", { error_message: "Please log in to access this page" });
    }
});

// Main page route - notice it checks if they have logged in
app.get("/login", (req, res) => {
    // Always show the login page
    res.render("login", { error_message: "" });
});

app.get("/test", (req, res) => {
    // Check if user is logged in
    if (req.session.isLoggedIn) {
        res.render("test", { name: "BYU" });
    }
    else {
        res.render("login", { error_message: "" });
    }
});

app.get("/users", (req, res) => {
    // Check if user is logged in
    if (req.session.isLoggedIn) {
        knex.select().from("users")
            .then(users => {
                console.log(`Successfully retrieved ${users.length} users from database`);
                res.render("displayUsers", { users: users });
            })
            .catch((err) => {
                console.error("Database query error:", err.message);
                res.render("displayUsers", {
                    users: [],
                    error_message: `Database error: ${err.message}. Please check if the 'users' table exists.`
                });
            });
    }
    else {
        res.render("login", { error_message: "" });
    }
});

app.get("/", async (req, res) => {
    // Always show the homepage (index.ejs)
    // Pass user info if logged in
    const userInfo = await getUserInfo(req);
    res.render("index", { user: userInfo });
});

// Events route
app.get("/events", async (req, res) => {
    const userInfo = await getUserInfo(req);

    // Query to get events with their occurrence details
    // Use DISTINCT ON eventname to get unique event names
    knex.raw(`
        SELECT DISTINCT ON (events.eventname)
            events.eventid,
            events.eventname,
            events.eventdescription,
            events.eventtype,
            events.eventrecurrencepattern,
            events.eventdefaultcapacity,
            events.eventimage,
            eventoccurrence.eventdatetimestart,
            eventoccurrence.eventlocation
        FROM events
        LEFT JOIN eventoccurrence ON events.eventid = eventoccurrence.eventid
        ORDER BY events.eventname, events.eventid
    `)
        .then(result => {
            const events = result.rows || result; // Handle raw query result
            console.log(`Successfully retrieved ${events.length} events from database`);
            res.render("events", {
                user: userInfo,
                events: events
            });
        })
        .catch(err => {
            console.error("Database query error:", err.message);
            res.render("events", {
                user: userInfo,
                events: [],
                error_message: `Database error: ${err.message}. Please check if the tables exist.`
            });
        });
});

// Events POST route - Add Event (Manager only)
app.post("/events/add", (req, res) => {
    // Check if user is logged in as manager
    if (!req.session.isLoggedIn || req.session.level !== 'M') {
        return res.status(403).json({ error: 'Unauthorized. Manager access required.' });
    }

    const { eventName, eventDescription, eventType, eventRecurrencePattern, eventDefaultCapacity } = req.body;

    if (!eventName || !eventDescription || !eventType || !eventRecurrencePattern || !eventDefaultCapacity) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    knex('events')
        .insert({
            eventname: eventName,
            eventdescription: eventDescription,
            eventtype: eventType,
            eventrecurrencepattern: eventRecurrencePattern,
            eventdefaultcapacity: parseInt(eventDefaultCapacity) || null
        })
        .returning('eventid')
        .then(result => {
            console.log(`Event added successfully with ID: ${result[0].eventid}`);
            res.json({ success: true, eventId: result[0].eventid, message: 'Event added successfully' });
        })
        .catch(err => {
            console.error("Error adding event:", err.message);
            res.status(500).json({ error: `Database error: ${err.message}` });
        });
});

// Events POST route - Edit Event (Manager only)
app.post("/events/edit/:id", (req, res) => {
    // Check if user is logged in as manager
    if (!req.session.isLoggedIn || req.session.level !== 'M') {
        return res.status(403).json({ error: 'Unauthorized. Manager access required.' });
    }

    const eventId = req.params.id;
    const { eventName, eventDescription, eventType, eventRecurrencePattern, eventDefaultCapacity } = req.body;

    if (!eventName || !eventDescription || !eventType || !eventRecurrencePattern || !eventDefaultCapacity) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    knex('events')
        .where('eventid', eventId)
        .update({
            eventname: eventName,
            eventdescription: eventDescription,
            eventtype: eventType,
            eventrecurrencepattern: eventRecurrencePattern,
            eventdefaultcapacity: parseInt(eventDefaultCapacity) || null
        })
        .then(result => {
            if (result === 0) {
                return res.status(404).json({ error: 'Event not found' });
            }
            console.log(`Event ${eventId} updated successfully`);
            res.json({ success: true, message: 'Event updated successfully' });
        })
        .catch(err => {
            console.error("Error updating event:", err.message);
            res.status(500).json({ error: `Database error: ${err.message}` });
        });
});

// Events POST route - Delete Event (Manager only)
app.post("/events/delete/:id", (req, res) => {
    // Check if user is logged in as manager
    if (!req.session.isLoggedIn || req.session.level !== 'M') {
        return res.status(403).json({ error: 'Unauthorized. Manager access required.' });
    }

    const eventId = req.params.id;

    // First delete related eventoccurrence records
    knex('eventoccurrence')
        .where('eventid', eventId)
        .del()
        .then(() => {
            // Then delete the event
            return knex('events')
                .where('eventid', eventId)
                .del();
        })
        .then(result => {
            if (result === 0) {
                return res.status(404).json({ error: 'Event not found' });
            }
            console.log(`Event ${eventId} deleted successfully`);
            res.json({ success: true, message: 'Event deleted successfully' });
        })
        .catch(err => {
            console.error("Error deleting event:", err.message);
            res.status(500).json({ error: `Database error: ${err.message}` });
        });
});

// Participants route
app.get("/participants", async (req, res) => {
    const userInfo = await getUserInfo(req);

    // Query to get all participants from database
    knex.select()
        .from('participants')
        .orderBy('participantlastname', 'asc')
        .then(participants => {
            console.log(`Successfully retrieved ${participants.length} participants from database`);
            res.render("participants", {
                user: userInfo,
                participants: participants || []
            });
        })
        .catch(err => {
            console.error("Database query error:", err.message);
            res.render("participants", {
                user: userInfo,
                participants: [],
                error_message: `Database error: ${err.message}. Please check if the 'participants' table exists.`
            });
        });
});

// Participants POST route - Add Participant (Manager only)
app.post("/participants/add", (req, res) => {
    // Check if user is logged in as manager
    if (!req.session.isLoggedIn || req.session.level !== 'M') {
        return res.status(403).json({ error: 'Unauthorized. Manager access required.' });
    }

    const {
        participantEmail,
        participantFirstName,
        participantLastName,
        participantDOB,
        participantRole,
        participantPhone,
        participantCity,
        participantState,
        participantZip,
        participantSchoolOrEmployer,
        participantFieldOfInterest
    } = req.body;

    if (!participantEmail || !participantFirstName || !participantLastName) {
        return res.status(400).json({ error: 'Email, First Name, and Last Name are required fields' });
    }

    knex('participants')
        .insert({
            participantemail: participantEmail,
            participantfirstname: participantFirstName,
            participantlastname: participantLastName,
            participantdob: participantDOB || null,
            participantrole: participantRole || null,
            participantphone: participantPhone || null,
            participantcity: participantCity || null,
            participantstate: participantState || null,
            participantzip: participantZip || null,
            participantschooloremployer: participantSchoolOrEmployer || null,
            participantfieldofinterest: participantFieldOfInterest || null
        })
        .returning('participantid')
        .then(result => {
            console.log(`Participant added successfully with ID: ${result[0].participantid}`);
            res.json({ success: true, participantId: result[0].participantid, message: 'Participant added successfully' });
        })
        .catch(err => {
            console.error("Error adding participant:", err.message);
            res.status(500).json({ error: `Database error: ${err.message}` });
        });
});

// Participants POST route - Edit Participant (Manager only)
app.post("/participants/edit/:id", (req, res) => {
    // Check if user is logged in as manager
    if (!req.session.isLoggedIn || req.session.level !== 'M') {
        return res.status(403).json({ error: 'Unauthorized. Manager access required.' });
    }

    const participantId = req.params.id;
    const {
        participantEmail,
        participantFirstName,
        participantLastName,
        participantDOB,
        participantRole,
        participantPhone,
        participantCity,
        participantState,
        participantZip,
        participantSchoolOrEmployer,
        participantFieldOfInterest
    } = req.body;

    if (!participantEmail || !participantFirstName || !participantLastName) {
        return res.status(400).json({ error: 'Email, First Name, and Last Name are required fields' });
    }

    knex('participants')
        .where('participantid', participantId)
        .update({
            participantemail: participantEmail,
            participantfirstname: participantFirstName,
            participantlastname: participantLastName,
            participantdob: participantDOB || null,
            participantrole: participantRole || null,
            participantphone: participantPhone || null,
            participantcity: participantCity || null,
            participantstate: participantState || null,
            participantzip: participantZip || null,
            participantschooloremployer: participantSchoolOrEmployer || null,
            participantfieldofinterest: participantFieldOfInterest || null
        })
        .then(result => {
            if (result === 0) {
                return res.status(404).json({ error: 'Participant not found' });
            }
            console.log(`Participant ${participantId} updated successfully`);
            res.json({ success: true, message: 'Participant updated successfully' });
        })
        .catch(err => {
            console.error("Error updating participant:", err.message);
            res.status(500).json({ error: `Database error: ${err.message}` });
        });
});

// Participants POST route - Delete Participant (Manager only)
app.post("/participants/delete/:id", (req, res) => {
    // Check if user is logged in as manager
    if (!req.session.isLoggedIn || req.session.level !== 'M') {
        return res.status(403).json({ error: 'Unauthorized. Manager access required.' });
    }

    const participantId = req.params.id;

    knex('participants')
        .where('participantid', participantId)
        .del()
        .then(result => {
            if (result === 0) {
                return res.status(404).json({ error: 'Participant not found' });
            }
            console.log(`Participant ${participantId} deleted successfully`);
            res.json({ success: true, message: 'Participant deleted successfully' });
        })
        .catch(err => {
            console.error("Error deleting participant:", err.message);
            res.status(500).json({ error: `Database error: ${err.message}` });
        });
});

// Milestones route
app.get("/milestones", async (req, res) => {
    const userInfo = await getUserInfo(req);
    res.render("milestones", { user: userInfo });
});

// Dashboard route
app.get("/dashboard", async (req, res) => {
    const userInfo = await getUserInfo(req);
    res.render("dashboard", { user: userInfo });
});

// Personal Milestones route
app.get("/personal-milestones", async (req, res) => {
    const userInfo = await getUserInfo(req);

    const participantId = req.query.participantId;
    let participant = null;
    let milestones = [];

    try {
        if (participantId) {
            participant = await knex("participants").where("participantid", participantId).first();
        } else if (req.query.email) {
            participant = await knex("participants").where("participantemail", req.query.email).first();
        }

        if (participant) {
            milestones = await knex("milestones")
                .where("participantid", participant.participantid)
                .orderBy("milestonedate", "desc")
                .select("milestonetitle", "milestonedate");
        }
    } catch (err) {
        console.error("Error fetching participant/milestones:", err);
    }

    res.render("personal-milestones", {
        user: userInfo,
        participant: participant ? {
            id: participant.participantid,
            name: `${participant.participantfirstname} ${participant.participantlastname}`,
            email: participant.participantemail
        } : null,
        milestonesJson: JSON.stringify(milestones.map(m => ({
            milestone_name: m.milestonetitle,
            date_achieved: m.milestonedate
        }))),
        milestones: milestones.map(m => ({
            milestone_name: m.milestonetitle,
            date_achieved: m.milestonedate
        })),
        participantName: participant ? `${participant.participantfirstname} ${participant.participantlastname}` : (req.query.name || 'Participant'),
        participantEmail: participant ? participant.participantemail : (req.query.email || '')
    });
});

// My Journey route (for logged-in users viewing their own milestones)
app.get("/my-journey", async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect("/login");
    }
    const userInfo = await getUserInfo(req);

    let participant = null;
    let milestones = [];

    try {
        // Try to find participant by participantid from session first, then by email
        if (req.session.participantid) {
            participant = await knex("participants").where("participantid", req.session.participantid).first();
        }
        
        if (!participant) {
            // Fallback to email lookup
            participant = await knex("participants").where("participantemail", req.session.username).first();
        }

        if (participant) {
            milestones = await knex("milestones")
                .where("participantid", participant.participantid)
                .orderBy("milestonedate", "desc")
                .select("milestonetitle", "milestonedate");
        }
    } catch (err) {
        console.error("Error fetching my journey:", err);
    }

    res.render("personal-milestones", {
        user: userInfo,
        participant: participant ? {
            id: participant.participantid,
            name: `${participant.participantfirstname} ${participant.participantlastname}`,
            email: participant.participantemail
        } : null,
        milestonesJson: JSON.stringify(milestones.map(m => ({
            milestone_name: m.milestonetitle,
            date_achieved: m.milestonedate
        }))),
        milestones: milestones.map(m => ({
            milestone_name: m.milestonetitle,
            date_achieved: m.milestonedate
        })),
        participantName: participant ? `${participant.participantfirstname} ${participant.participantlastname}` : userInfo.full_name,
        participantEmail: participant ? participant.participantemail : req.session.username
    });
});

// RSVP route
app.get("/rsvp", async (req, res) => {
    const userInfo = await getUserInfo(req);
    res.render("rsvp", { user: userInfo });
});

// Survey route - GET (singular)
app.get("/survey", async (req, res) => {
    const userInfo = await getUserInfo(req);

    // Query to get events with DISTINCT ON eventname (similar to events page)
    knex.raw(`
        SELECT DISTINCT ON (events.eventname)
            events.eventid,
            events.eventname,
            events.eventdescription,
            eventoccurrence.eventoccurrenceid,
            eventoccurrence.eventlocation
        FROM events
        LEFT JOIN eventoccurrence ON events.eventid = eventoccurrence.eventid
        ORDER BY events.eventname, events.eventid
    `)
        .then(result => {
            const events = result.rows || result;

            // Get all occurrences for all events to populate dropdown
            return knex.select(
                'eventoccurrence.eventoccurrenceid',
                'eventoccurrence.eventid',
                'eventoccurrence.eventdatetimestart'
            )
                .from('eventoccurrence')
                .orderBy('eventoccurrence.eventdatetimestart', 'asc')
                .then(occurrences => {
                    // Group occurrences by eventid
                    const occurrencesByEvent = {};
                    occurrences.forEach(occ => {
                        if (!occurrencesByEvent[occ.eventid]) {
                            occurrencesByEvent[occ.eventid] = [];
                        }
                        occurrencesByEvent[occ.eventid].push(occ);
                    });

                    console.log(`Successfully retrieved ${events.length} events and ${occurrences.length} occurrences for survey from database`);
                    res.render("survey", {
                        user: userInfo,
                        events: events,
                        occurrencesByEvent: occurrencesByEvent
                    });
                });
        })
        .catch(err => {
            console.error("Database query error:", err.message);
            res.render("survey", {
                user: userInfo,
                events: [],
                occurrencesByEvent: {},
                error_message: `Database error: ${err.message}. Please check if the tables exist.`
            });
        });
});

// Survey route - GET (plural - for consistency)
app.get("/surveys", async (req, res) => {
    const userInfo = await getUserInfo(req);

    // Query to get events with DISTINCT ON eventname (similar to events page)
    knex.raw(`
        SELECT DISTINCT ON (events.eventname)
            events.eventid,
            events.eventname,
            events.eventdescription,
            eventoccurrence.eventoccurrenceid,
            eventoccurrence.eventlocation
        FROM events
        LEFT JOIN eventoccurrence ON events.eventid = eventoccurrence.eventid
        ORDER BY events.eventname, events.eventid
    `)
        .then(result => {
            const events = result.rows || result;

            // Get all occurrences for all events to populate dropdown
            return knex.select(
                'eventoccurrence.eventoccurrenceid',
                'eventoccurrence.eventid',
                'eventoccurrence.eventdatetimestart'
            )
                .from('eventoccurrence')
                .orderBy('eventoccurrence.eventdatetimestart', 'asc')
                .then(occurrences => {
                    // Group occurrences by eventid
                    const occurrencesByEvent = {};
                    occurrences.forEach(occ => {
                        if (!occurrencesByEvent[occ.eventid]) {
                            occurrencesByEvent[occ.eventid] = [];
                        }
                        occurrencesByEvent[occ.eventid].push(occ);
                    });

                    console.log(`Successfully retrieved ${events.length} events and ${occurrences.length} occurrences for survey from database`);
                    res.render("survey", {
                        user: userInfo,
                        events: events,
                        occurrencesByEvent: occurrencesByEvent
                    });
                });
        })
        .catch(err => {
            console.error("Database query error:", err.message);
            res.render("survey", {
                user: userInfo,
                events: [],
                occurrencesByEvent: {},
                error_message: `Database error: ${err.message}. Please check if the tables exist.`
            });
        });
});

// Survey route - POST (save survey responses to database)
app.post("/survey", (req, res) => {
    const { eventName, eventId, email, eventoccurrenceid, satisfactionScore, usefulnessScore, instructorScore, recommendationScore, comments } = req.body;

            // Get or create participant ID from email
    knex.select('participantid')
        .from('participants')
        .where('participantemail', email)
        .first()
        .then(participant => {
            if (participant) {
                return participant.participantid;
    } else {
                // Create new participant if doesn't exist
                // Try to get name from user's participant record if available
                let firstName = '';
                let lastName = '';
                
                if (req.session.participantid) {
                    return knex('participants')
                        .where('participantid', req.session.participantid)
                        .first()
                        .then(userParticipant => {
                            if (userParticipant) {
                                firstName = userParticipant.participantfirstname || '';
                                lastName = userParticipant.participantlastname || '';
                            }
                            return knex('participants')
                                .insert({
                                    participantemail: email,
                                    participantfirstname: firstName,
                                    participantlastname: lastName
                                })
                                .returning('participantid')
                                .then(ids => ids[0].participantid);
                        });
                } else {
                    return knex('participants')
                        .insert({
                            participantemail: email,
                            participantfirstname: '',
                            participantlastname: ''
                        })
                        .returning('participantid')
                        .then(ids => ids[0].participantid);
                }
            }
        })
        .then(participantId => {
            // Get eventoccurrenceid if not provided
            let eventOccurrenceId = eventoccurrenceid;
            if (!eventOccurrenceId && eventId) {
                return knex.select('eventoccurrenceid')
                    .from('eventoccurrence')
                    .where('eventid', eventId)
                    .first()
                    .then(occurrence => {
                        if (occurrence) {
                            eventOccurrenceId = occurrence.eventoccurrenceid;
                        }
                        return { participantId, eventOccurrenceId };
                    });
            }
            return { participantId, eventOccurrenceId };
        })
        .then(({ participantId, eventOccurrenceId }) => {
            if (!eventOccurrenceId) {
                throw new Error('Event occurrence ID not found');
            }

            // Calculate OverallScore as average of rating scores
            const scores = [
                parseFloat(satisfactionScore),
                parseFloat(usefulnessScore),
                parseFloat(instructorScore),
                parseFloat(recommendationScore)
            ].filter(score => !isNaN(score));

            const overallScore = scores.length > 0
                ? (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(2)
                : null;

            // Calculate NPSBucket based on RecommendationScore
            const recScore = parseFloat(recommendationScore);
            let npsBucket = 'Detractor';
            if (recScore === 5) {
                npsBucket = 'Promoter';
            } else if (recScore === 4) {
                npsBucket = 'Passive';
            }

            // Format date as YYYY-MM-DD HH:MM:SS
            const now = new Date();
            const year = now.getFullYear();
            const month = String(now.getMonth() + 1).padStart(2, '0');
            const day = String(now.getDate()).padStart(2, '0');
            const hours = String(now.getHours()).padStart(2, '0');
            const minutes = String(now.getMinutes()).padStart(2, '0');
            const seconds = String(now.getSeconds()).padStart(2, '0');
            const formattedDate = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;

            // Insert survey responses - one row per question
            const surveyResponses = [
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'SatisfactionScore', surveyanswer: satisfactionScore },
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'UsefulnessScore', surveyanswer: usefulnessScore },
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'InstructorScore', surveyanswer: instructorScore },
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'RecommendationScore', surveyanswer: recommendationScore },
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'OverallScore', surveyanswer: overallScore },
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'NPSBucket', surveyanswer: npsBucket },
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'Comments', surveyanswer: comments || '' },
                { participantid: participantId, eventoccurrenceid: eventOccurrenceId, surveyquestion: 'SubmissionDate', surveyanswer: formattedDate }
            ];

            return knex('surveyresponses').insert(surveyResponses);
        })
        .then(() => {
            console.log("Survey submitted successfully");
            res.redirect("/survey?success=true");
        })
        .catch(err => {
            console.error("Survey submission error:", err);
            res.redirect("/survey?error=" + encodeURIComponent(err.message));
        });
});

// Survey route - POST (plural - redirects to singular)
app.post("/surveys", (req, res) => {
    // Redirect to singular route handler
    req.url = '/survey';
    return app._router.handle(req, res);
});

// This creates attributes in the session object to keep track of user and if they logged in
app.post("/login", (req, res) => {
    let sName = req.body.username;
    let sPassword = req.body.password;

    knex.select("username", "password", "level", "participantid")
        .from('users')
        .where("username", sName)
        .andWhere("password", sPassword)
        .then(users => {
            // Check if a user was found with matching username AND password
            if (users.length > 0) {
                req.session.isLoggedIn = true;
                req.session.username = sName;
                req.session.level = users[0].level; // Store the user's level (M or U)
                req.session.participantid = users[0].participantid || null;
                res.redirect("/");
            } else {
                // No matching user found
                res.render("login", { error_message: "Invalid login" });
            }
        })
        .catch(err => {
            console.error("Login error:", err);
            res.render("login", { error_message: "Invalid login" });
        });
});

// Signup route - GET
app.get("/signup", (req, res) => {
    res.render("login", { error_message: "" });
});

// Signup route - POST
app.post("/signup", (req, res) => {
    console.log("=== SIGNUP ROUTE HIT ===");
    console.log("Request body:", req.body);
    console.log("Request method:", req.method);
    console.log("Request URL:", req.url);

    const { username, password, first_name, last_name } = req.body;

    console.log("Signup attempt:", { username, first_name, last_name, hasPassword: !!password });

    // Basic validation
    if (!username || !password || !first_name || !last_name) {
        console.log("Validation failed - missing fields");
        return res.render("login", { error_message: "All fields are required." });
    }

    // Check if username already exists
    knex("users")
        .where("username", username)
        .first()
        .then((existingUser) => {
            if (existingUser) {
                console.log("Username already exists:", username);
                return res.render("login", { error_message: "Username already exists. Please choose another." });
            }

            // First create participant record
            return knex("participants")
                .insert({
                    participantemail: username,
                    participantfirstname: first_name,
                    participantlastname: last_name
                })
                .returning('participantid')
                .then(participantIds => {
                    const participantid = participantIds[0].participantid;
                    
                    // Create new user with level 'U' (User) and link to participant
                    const newUser = {
                        username,
                        password,
                        participantid: participantid,
                        level: 'U'
                    };

                    console.log("Attempting to insert user:", newUser);

                    // Insert the new user
                    return knex("users")
                        .insert(newUser)
                        .then(() => {
                            console.log("User created successfully:", username);
                            // Automatically sign them in and redirect to homepage
                            req.session.isLoggedIn = true;
                            req.session.username = username;
                            req.session.level = 'U';
                            req.session.participantid = participantid;
                            res.redirect("/");
                        });
                });
        })
        .catch((dbErr) => {
            console.error("Error creating user:", dbErr);
            console.error("Error details:", dbErr.message);
            res.render("login", { error_message: `Unable to create account: ${dbErr.message}` });
        })
        .catch((err) => {
            console.error("Error checking username:", err);
            console.error("Error details:", err.message);
            res.render("login", { error_message: `An error occurred: ${err.message}` });
        });
});

// Logout route
app.get("/logout", (req, res) => {
    // Get rid of the session object
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
        }
        res.redirect("/");
    });
});

app.get("/addUser", (req, res) => {
    res.render("addUser");
});

app.post("/addUser", upload.single("profileImage"), (req, res) => {
    // Destructuring grabs them regardless of field order.
    //const username = req.body.username;
    //const password = req.body.password;

    const { username, password } = req.body;

    // Basic validation to ensure required fields are present.
    if (!username || !password) {
        return res.status(400).render("addUser", { error_message: "Username and password are required." });
    }

    // Build the relative path to the uploaded file so the 
    // browser can load it later.
    const profileImagePath = req.file ? `/images/uploads/${req.file.filename}` : null;

    // Shape the data to match the users table schema.
    // Object literal - other languages use dictionaries
    // When the object is inserted with Knex, that value profileImagePath,
    // becomes the database column profile_image, so the saved path to 
    // the uploaded image ends up in the profile_image column for that user.
    const newUser = {
        username,
        password,
        profile_image: profileImagePath
    };

    // Insert the record into PostgreSQL and return the user list on success.
    knex("users")
        .insert(newUser)
        .then(() => {
            res.redirect("/users");
        })
        .catch((dbErr) => {
            console.error("Error inserting user:", dbErr.message);
            // Database error, so show the form again with a generic message.
            res.status(500).render("addUser", { error_message: "Unable to save user. Please try again." });
        });
});

app.get("/editUser/:id", (req, res) => {
    const userId = req.params.id;

    knex("users")
        .where({ id: userId })
        .first()
        .then((user) => {
            if (!user) {
                return res.status(404).render("displayUsers", {
                    users: [],
                    error_message: "User not found."
                });
            }

            res.render("editUser", { user, error_message: "" });
        })
        .catch((err) => {
            console.error("Error fetching user:", err.message);
            res.status(500).render("displayUsers", {
                users: [],
                error_message: "Unable to load user for editing."
            });
        });
});

app.post("/editUser/:id", upload.single("profileImage"), (req, res) => {
    const userId = req.params.id;
    const { username, password, existingImage } = req.body;

    if (!username || !password) {
        return knex("users")
            .where({ id: userId })
            .first()
            .then((user) => {
                if (!user) {
                    return res.status(404).render("displayUsers", {
                        users: [],
                        error_message: "User not found."
                    });
                }

                res.status(400).render("editUser", {
                    user,
                    error_message: "Username and password are required."
                });
            })
            .catch((err) => {
                console.error("Error fetching user:", err.message);
                res.status(500).render("displayUsers", {
                    users: [],
                    error_message: "Unable to load user for editing."
                });
            });
    }

    const profileImagePath = req.file ? `/images/uploads/${req.file.filename}` : existingImage || null;

    const updatedUser = {
        username,
        password,
        profile_image: profileImagePath
    };

    knex("users")
        .where({ id: userId })
        .update(updatedUser)
        .then((rowsUpdated) => {
            if (rowsUpdated === 0) {
                return res.status(404).render("displayUsers", {
                    users: [],
                    error_message: "User not found."
                });
            }

            res.redirect("/users");
        })
        .catch((err) => {
            console.error("Error updating user:", err.message);
            knex("users")
                .where({ id: userId })
                .first()
                .then((user) => {
                    if (!user) {
                        return res.status(404).render("displayUsers", {
                            users: [],
                            error_message: "User not found."
                        });
                    }

                    res.status(500).render("editUser", {
                        user,
                        error_message: "Unable to update user. Please try again."
                    });
                })
                .catch((fetchErr) => {
                    console.error("Error fetching user after update failure:", fetchErr.message);
                    res.status(500).render("displayUsers", {
                        users: [],
                        error_message: "Unable to update user."
                    });
                });
        });
});

app.get("/displayHobbies/:userId", (req, res) => {
    const userId = req.params.userId;

    knex("users")
        .where({ id: userId })
        .first()
        .then((user) => {
            if (!user) {
                return res.status(404).render("displayUsers", {
                    users: [],
                    error_message: "User not found."
                });
            }
            knex("hobbies")
                .where({ user_id: userId })
                .orderBy("id")
                .then((hobbies) => {
                    res.render("displayHobbies", {
                        user,
                        hobbies,
                        error_message: "",
                        success_message: ""
                    });
                })
                .catch((hobbyErr) => {
                    console.error("Error loading hobbies:", hobbyErr.message);
                    res.status(500).render("displayUsers", {
                        users: [],
                        error_message: "Unable to load hobbies."
                    });
                });
        })
        .catch((err) => {
            console.error("Error loading hobbies:", err.message);
            res.status(500).render("displayUsers", {
                users: [],
                error_message: "Unable to load hobbies."
            });
        });
});

app.get("/addHobbies/:userId", (req, res) => {
    const userId = req.params.userId;

    knex("users")
        .where({ id: userId })
        .first()
        .then((user) => {
            if (!user) {
                return res.status(404).render("displayUsers", {
                    users: [],
                    error_message: "User not found."
                });
            }
            res.render("addHobbies", {
                user,
                error_message: ""
            });
        })
        .catch((err) => {
            console.error("Error loading user:", err.message);
            res.status(500).render("displayUsers", {
                users: [],
                error_message: "Unable to load user."
            });
        });
});

app.post("/addHobbies/:userId", (req, res) => {
    const userId = req.params.userId;
    const hobby_description = (req.body.hobby_description || "").trim();
    const date_learned = req.body.date_learned;

    if (!hobby_description || !date_learned) {
        return knex("users")
            .where({ id: userId })
            .first()
            .then((user) => {
                if (!user) {
                    return res.status(404).render("displayUsers", {
                        users: [],
                        error_message: "User not found."
                    });
                }
                res.status(400).render("addHobbies", {
                    user,
                    error_message: "Hobby description and date learned are required."
                });
            })
            .catch((err) => {
                console.error("Error validating hobby:", err.message);
                res.status(500).render("displayUsers", {
                    users: [],
                    error_message: "Unable to add hobby."
                });
            });
    }

    knex("hobbies")
        .insert({ user_id: userId, hobby_description, date_learned })
        .then(() => {
            res.redirect(`/displayHobbies/${userId}`);
        })
        .catch((err) => {
            console.error("Error inserting hobby:", err.message);
            knex("users")
                .where({ id: userId })
                .first()
                .then((user) => {
                    if (!user) {
                        return res.status(404).render("displayUsers", {
                            users: [],
                            error_message: "User not found."
                        });
                    }
                    res.status(500).render("addHobbies", {
                        user,
                        error_message: "Unable to add hobby. Please try again."
                    });
                })
                .catch((userErr) => {
                    console.error("Error fetching user after hobby insert failure:", userErr.message);
                    res.status(500).render("displayUsers", {
                        users: [],
                        error_message: "Unable to add hobby."
                    });
                });
        });
});

app.post("/hobbies/:userId/delete/:hobbyId", (req, res) => {
    const { userId, hobbyId } = req.params;

    knex("hobbies")
        .where({ id: hobbyId, user_id: userId })
        .del()
        .then(() => {
            res.redirect(`/displayHobbies/${userId}`);
        })
        .catch((err) => {
            console.error("Error deleting hobby:", err.message);
            knex("users")
                .where({ id: userId })
                .first()
                .then((user) => {
                    if (!user) {
                        return res.status(404).render("displayUsers", {
                            users: [],
                            error_message: "User not found."
                        });
                    }
                    knex("hobbies")
                        .where({ user_id: userId })
                        .orderBy("id")
                        .then((hobbies) => {
                            res.status(500).render("displayHobbies", {
                                user,
                                hobbies,
                                error_message: "Unable to delete hobby. Please try again.",
                                success_message: ""
                            });
                        })
                        .catch((fetchErr) => {
                            console.error("Error fetching after delete failure:", fetchErr.message);
                            res.status(500).render("displayUsers", {
                                users: [],
                                error_message: "Unable to delete hobby."
                            });
                        });
                })
                .catch((userErr) => {
                    console.error("Error fetching user after delete failure:", userErr.message);
                    res.status(500).render("displayUsers", {
                        users: [],
                        error_message: "Unable to delete hobby."
                    });
                });
        });
});

app.post("/deleteUser/:id", (req, res) => {
    knex("users").where("id", req.params.id).del().then(users => {
        res.redirect("/users");
    }).catch(err => {
        console.log(err);
        res.status(500).json({ err });
    })
});

app.get('/teapot', (req, res) => {
    res.status(418).render('teapot');

});


// API Routes for Milestones Feature

// Search participants
app.get("/api/participants", (req, res) => {
    const search = req.query.search || "";
    knex("participants")
        .where("participantfirstname", "ilike", `%${search}%`)
        .orWhere("participantlastname", "ilike", `%${search}%`)
        .orWhere("participantemail", "ilike", `%${search}%`)
        .select("participantid", "participantfirstname", "participantlastname", "participantemail")
        .limit(10)
        .then(participants => {
            const mappedParticipants = participants.map(p => ({
                id: p.participantid,
                name: `${p.participantfirstname} ${p.participantlastname}`,
                email: p.participantemail
            }));
            res.json(mappedParticipants);
        })
        .catch(err => {
            console.error("Error searching participants:", err);
            res.status(500).json({ error: "Database error" });
        });
});

// Get milestones for a participant
app.get("/api/participants/:id/milestones", (req, res) => {
    const participantId = req.params.id;
    knex("milestones")
        .where("participantid", participantId)
        .select("milestonetitle", "milestonedate")
        .orderBy("milestonedate", "desc")
        .then(milestones => {
            const mappedMilestones = milestones.map(m => ({
                milestone_name: m.milestonetitle,
                date_achieved: m.milestonedate
            }));
            res.json(mappedMilestones);
        })
        .catch(err => {
            console.error("Error fetching milestones:", err);
            res.status(500).json({ error: "Database error" });
        });
});

// Assign milestone
app.post("/api/milestones", (req, res) => {
    const { participant_id, milestone_name } = req.body;

    if (!participant_id || !milestone_name) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    knex("milestones")
        .insert({
            participantid: participant_id,
            milestonetitle: milestone_name,
            milestonedate: new Date()
        })
        .then(() => {
            res.json({ success: true });
        })
        .catch(err => {
            console.error("Error assigning milestone:", err);
            res.status(500).json({ error: "Database error" });
        });
});

app.listen(port, () => {
    console.log("The server is listening");
});