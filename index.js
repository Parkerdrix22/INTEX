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
        host: process.env.RDS_HOSTNAME || "localhost",
        user: process.env.RDS_USERNAME || "postgres",
        password: process.env.RDS_PASSWORD || "admin",
        database: process.env.RDS_DB_NAME || "intex",
        port: process.env.RDS_PORT || 5432,
        // The new part 
        ssl: process.env.DB_SSL ? {rejectUnauthorized: false} : false 
    }
});

// Tells Express how to read form data sent in the body of a request
app.use(express.urlencoded({extended: true}));

// Global authentication middleware - runs on EVERY request
app.use((req, res, next) => {
    // Skip authentication for login routes, signup, events, and survey
    if (req.path === '/' || req.path === '/login' || req.path === '/logout' || req.path === '/signup' || req.path === '/events' || req.path === '/rsvp' || req.path === '/survey' || req.path === '/surveys' || req.path === '/participants' || req.path === '/milestones') {
        //continue with the request path
        return next();
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
        res.render("test", {name : "BYU"});
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
                res.render("displayUsers", {users: users});
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

app.get("/", (req, res) => {
    // Always show the homepage (index.ejs)
    // Pass user info if logged in
    const userInfo = req.session.isLoggedIn ? {
        username: req.session.username,
        first_name: req.session.first_name,
        last_name: req.session.last_name,
        full_name: `${req.session.first_name || ''} ${req.session.last_name || ''}`.trim() || req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U'
    } : null;
    
    res.render("index", { user: userInfo });
});

// Events route
app.get("/events", (req, res) => {
    const userInfo = req.session.isLoggedIn ? {
        username: req.session.username,
        first_name: req.session.first_name,
        last_name: req.session.last_name,
        full_name: `${req.session.first_name || ''} ${req.session.last_name || ''}`.trim() || req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U'
    } : null;
    res.render("events", { user: userInfo });
});

// Participants route
app.get("/participants", (req, res) => {
    const userInfo = req.session.isLoggedIn ? {
        username: req.session.username,
        first_name: req.session.first_name,
        last_name: req.session.last_name,
        full_name: `${req.session.first_name || ''} ${req.session.last_name || ''}`.trim() || req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U'
    } : null;
    res.render("participants", { user: userInfo });
});

// Milestones route
app.get("/milestones", (req, res) => {
    const userInfo = req.session.isLoggedIn ? {
        username: req.session.username,
        first_name: req.session.first_name,
        last_name: req.session.last_name,
        full_name: `${req.session.first_name || ''} ${req.session.last_name || ''}`.trim() || req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U'
    } : null;
    res.render("milestones", { user: userInfo });
});

// RSVP route
app.get("/rsvp", (req, res) => {
    const userInfo = req.session.isLoggedIn ? {
        username: req.session.username,
        first_name: req.session.first_name,
        last_name: req.session.last_name,
        full_name: `${req.session.first_name || ''} ${req.session.last_name || ''}`.trim() || req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U'
    } : null;
    res.render("rsvp", { user: userInfo });
});

// Survey route - GET (singular)
app.get("/survey", (req, res) => {
    const userInfo = req.session.isLoggedIn ? {
        username: req.session.username,
        first_name: req.session.first_name,
        last_name: req.session.last_name,
        full_name: `${req.session.first_name || ''} ${req.session.last_name || ''}`.trim() || req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U'
    } : null;
    res.render("survey", { user: userInfo });
});

// Survey route - GET (plural - for consistency)
app.get("/surveys", (req, res) => {
    const userInfo = req.session.isLoggedIn ? {
        username: req.session.username,
        first_name: req.session.first_name,
        last_name: req.session.last_name,
        full_name: `${req.session.first_name || ''} ${req.session.last_name || ''}`.trim() || req.session.username,
        level: req.session.level,
        isManager: req.session.level === 'M',
        isUser: req.session.level === 'U'
    } : null;
    res.render("survey", { user: userInfo });
});

// Survey route - POST (placeholder - will be implemented later)
app.post("/survey", (req, res) => {
    // TODO: Save survey data to database
    console.log("Survey submitted:", req.body);
    res.redirect("/survey?success=true");
});

// Survey route - POST (plural)
app.post("/surveys", (req, res) => {
    // TODO: Save survey data to database
    console.log("Survey submitted:", req.body);
    res.redirect("/surveys?success=true");
});

// This creates attributes in the session object to keep track of user and if they logged in
app.post("/login", (req, res) => {
    let sName = req.body.username;
    let sPassword = req.body.password;
    
    knex.select("username", "password", "level", "first_name", "last_name")
        .from('users')
        .where("username", sName)
        .andWhere("password", sPassword)
        .then(users => {
            // Check if a user was found with matching username AND password
            if (users.length > 0) {
                req.session.isLoggedIn = true;
                req.session.username = sName;
                req.session.level = users[0].level; // Store the user's level (M or U)
                req.session.first_name = users[0].first_name;
                req.session.last_name = users[0].last_name;
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

            // Create new user with level 'U' (User)
            const newUser = {
                username,
                password,
                first_name,
                last_name,
                level: 'U'
            };

            console.log("Attempting to insert user:", newUser);

            // Insert the new user
            knex("users")
                .insert(newUser)
                .then(() => {
                    console.log("User created successfully:", username);
                    // Automatically sign them in and redirect to homepage
                    req.session.isLoggedIn = true;
                    req.session.username = username;
                    req.session.level = 'U';
                    req.session.first_name = first_name;
                    req.session.last_name = last_name;
                    res.redirect("/");
                })
                .catch((dbErr) => {
                    console.error("Error creating user:", dbErr);
                    console.error("Error details:", dbErr.message);
                    res.render("login", { error_message: `Unable to create account: ${dbErr.message}` });
                });
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
        res.status(500).json({err});
    })
});

app.listen(port, () => {
    console.log("The server is listening");
});