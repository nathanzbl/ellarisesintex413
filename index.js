//npm install dotenv - explain
//npm install express-session - explain
//create the .env file

// Load environment variables from .env file into memory
// Allows you to use process.env
require('dotenv').config();

const express = require("express");
const multer = require("multer");
const bcrypt = require('bcrypt');


//Needed for the session variable - Stored on the server to hold data
const session = require("express-session");

let path = require("path");

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

// process.env.PORT is when you deploy and 3000 is for test
const port = process.env.PORT || 3000;

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

// 403 handler
app.get("/forbidden", (req, res) => {
  res.status(403).render("403");
});

// 404 catch all



const knex = require("knex")({
    client: "pg",
    connection: {
        host : process.env.RDS_HOSTNAME || "database-1.cuxceiacqgo6.us-east-1.rds.amazonaws.com",
        user : process.env.RDS_USERNAME || "postgres",
        password : process.env.RDS_PASSWORD || "adminpassword12345",
        database : process.env.RDS_DB_NAME || "postgres",
        port : process.env.RDS_PORT || 5432,  // PostgreSQL 16 typically uses port 5434
        ssl: {
        rejectUnauthorized: false  // AWS RDS requires SSL
    }
    }
});

// Tells Express how to read form data sent in the body of a request
app.use(express.urlencoded({extended: true}));

// Global authentication middleware - runs on EVERY request
app.use((req, res, next) => {
    // Skip authentication for login routes
    if (req.path === '/' || req.path === '/login' || req.path === '/logout') {
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
    // Check if user is logged in
    if (req.session.isLoggedIn) {        
        res.render("landing");
    } 
    else {
        res.render("login", { error_message: "" });
    }
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


app.get("/surveys", (req, res) => {
    // Check if user is logged in
    if (req.session.isLoggedIn) {        
        knex.select("eventdefid","eventname").from("eventdefinition")
            .then(events => {
                res.render("surveys", {
                    events: events,
                    error_message: null
                });
            })
            .catch((err) => {
                console.error("Database query error:", err.message);
                res.render("surveys", {
                    events: [],
                    error_message: `Database error: ${err.message}`
                });
            });
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
    if (req.session.isLoggedIn) {
        res.render("landing");
    } else {
        res.redirect("/login");
    }
});

// This creates attributes in the session object to keep track of user and if they logged in
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Login attempt for user: ${username}`);

    try {
        // Query the database for the user
        const result = await knex.raw(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password.' 
            });
        }

        const user = result.rows[0];

        // Compare the provided password with the hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password.' 
            });
        }

        // Success! Store user info in session
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role
        };
        // Mark session as logged in so the auth middleware allows access
        req.session.isLoggedIn = true;
        // Redirect to main page
        return res.redirect('/');

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'An error occurred during login.' 
        });
    }
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

// Donation Routes
app.get("/donations", (req, res) => {
    res.render("donations");
});

// Milestone Routes
app.get("/milestones", (req, res) => {
    res.render("milestones");
});

// Participant Routes
app.get("/participants", (req, res) => {
    res.render("participants");
});


app.get("/register", (req, res) => {
    res.render("register");
});
app.post('/register', async (req, res) => {
    const { username, password, confirmPassword } = req.body;

    try {
        // Validation
        if (!username || !password || !confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'All fields are required.' 
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Passwords do not match.' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 6 characters long.' 
            });
        }

        // Check if username already exists
        const existingUser = await knex.raw(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username already exists.' 
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new owner into database
        await knex.raw(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, 'manager']
        );

        console.log(`✅ New manager registered: ${username}`);

        return res.status(200).json({ 
            success: true, 
            message: 'Manager registration successful!', 
            redirectTo: '/login' 
        });

    } catch (error) {
        console.error('Manager registration error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'An error occurred during registration.' 
        });
    }
});

app.post("/deleteUser/:id", (req, res) => {
    knex("users").where("id", req.params.id).del().then(users => {
        res.redirect("/users");
    }).catch(err => {
        console.log(err);
        res.status(500).json({err});
    })
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
            res.render("editUser", { user });
        })
        .catch((err) => {
            console.error("Error fetching user for edit:", err.message);
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
            });
});

// -----------------------------------------------------
//  EVENT SYSTEM ROUTES (PUBLIC + MANAGER)
// -----------------------------------------------------

// Middleware: Only allow managers
function requireManager(req, res, next) {
    if (!req.session.user) return res.status(403).render("403");

    const role = req.session.user.role.toLowerCase().trim();

    if (role === "manager" || role === "m") {
        return next();
    }

    return res.status(403).render("403");
}

// -----------------------------------------------------
// PUBLIC: Show next upcoming event
// -----------------------------------------------------
app.get("/eventspublic", async (req, res) => {
    try {
        const nextEvent = await knex("event")
            .join("eventdefinition", "event.eventdefid", "eventdefinition.eventdefid")
            .select(
                "event.eventid",
                "event.eventdatetimestart",
                "event.eventlocation",
                "eventdefinition.eventname",
                "eventdefinition.eventdescription"
            )
            .orderBy("event.eventdatetimestart", "asc")
            .first();

        res.render("eventspublic", { nextEvent });
    } catch (err) {
        console.error("Error loading public event list:", err);
        res.render("eventspublic", { nextEvent: null });
    }
});

// -----------------------------------------------------
// PUBLIC: Event Details Page
// -----------------------------------------------------
app.get("/events/detail/:id", async (req, res) => {
    try {
        const event = await knex("event")
            .join("eventdefinition", "event.eventdefid", "eventdefinition.eventdefid")
            .select(
                "event.*",
                "eventdefinition.eventname",
                "eventdefinition.eventdescription",
                "eventdefinition.eventtype",
                "eventdefinition.eventrecurrencepattern"
            )
            .where("event.eventid", req.params.id)
            .first();

        if (!event) return res.status(404).render("404");

        res.render("eventdetail", { event });
    } catch (err) {
        console.error("Error loading event detail:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// PUBLIC: RSVP Form Page
// -----------------------------------------------------
app.get("/events/rsvp/:id", async (req, res) => {
    try {
        const event = await knex("event")
            .join("eventdefinition", "event.eventdefid", "eventdefinition.eventdefid")
            .select(
                "event.eventid",
                "event.eventdatetimestart",
                "event.eventlocation",
                "eventdefinition.eventname"
            )
            .where("event.eventid", req.params.id)
            .first();

        if (!event) return res.status(404).render("404");

        res.render("eventrsvp", { event });
    } catch (err) {
        console.error("Error loading RSVP page:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// PUBLIC: Submit RSVP (placeholder)
// -----------------------------------------------------
app.post("/events/rsvp/:id", async (req, res) => {
    try {
        // TODO: Insert RSVP row into "eventrsvp" table later
        res.render("rsvpsuccess");
    } catch (err) {
        console.error("Error submitting RSVP:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// MANAGER: View All Events
// -----------------------------------------------------
app.get("/events", requireManager, async (req, res) => {
    try {
        let events = await knex("event")
            .join("eventdefinition", "event.eventdefid", "eventdefinition.eventdefid")
            .select(
                "event.eventid",
                "event.eventdatetimestart",
                "event.eventlocation",
                "eventdefinition.eventname"
            )
            .orderBy("event.eventdatetimestart", "asc");

        // Format each event's date
        events = events.map(ev => {
            const date = new Date(ev.eventdatetimestart);

            ev.formattedDate = date.toLocaleDateString("en-US", {
                month: "short",  // "Nov"
                day: "numeric",  // "7"
                year: "numeric"  // "2021"
            });

            return ev;
        });

        res.render("events", { events });
    } catch (err) {
        console.error("Error loading manager event list:", err);
        res.render("events", { events: [] });
    }
});

// -----------------------------------------------------
// MANAGER: Add Event Form
// -----------------------------------------------------
app.get("/events/add", requireManager, (req, res) => {
    res.render("addevent", { error_message: "" });
});

// -----------------------------------------------------
// MANAGER: Submit Add Event
// -----------------------------------------------------
app.post("/events/add", requireManager, async (req, res) => {
    try {
        // Step 1: Create event definition entry
        const [def] = await knex("eventdefinition")
            .insert({
                eventname: req.body.eventname,
                eventdescription: req.body.eventdescription,
                eventtype: req.body.eventtype,
                eventrecurrencepattern: req.body.eventrecurrencepattern
            })
            .returning("eventdefid");

        // Step 2: Create event entry linked to definition
        await knex("event").insert({
            eventdefid: def.eventdefid,
            eventdatetimestart: req.body.eventdatetimestart,
            eventdatetimeend: req.body.eventdatetimeend,
            eventlocation: req.body.eventlocation,
            eventcapacity: req.body.eventcapacity
        });

        res.redirect("/events");
    } catch (err) {
        console.error("Error adding event:", err);
        res.render("addevent", { error_message: "Error adding event." });
    }
});

// -----------------------------------------------------
// MANAGER: Edit Event Form
// -----------------------------------------------------
app.get("/events/edit/:id", requireManager, async (req, res) => {
    try {
        const event = await knex("event")
            .join("eventdefinition", "event.eventdefid", "eventdefinition.eventdefid")
            .select(
                "event.*",
                "eventdefinition.eventname",
                "eventdefinition.eventdescription",
                "eventdefinition.eventtype",
                "eventdefinition.eventrecurrencepattern"
            )
            .where("event.eventid", req.params.id)
            .first();

        if (!event) return res.status(404).render("404");

        res.render("editevent", { event });
    } catch (err) {
        console.error("Error loading edit form:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// MANAGER: Submit Edit Event
// -----------------------------------------------------
app.post("/events/edit/:id", requireManager, async (req, res) => {
    try {
        const event = await knex("event")
            .where("eventid", req.params.id)
            .first();

        // Update eventdefinition
        await knex("eventdefinition")
            .where("eventdefid", event.eventdefid)
            .update({
                eventname: req.body.eventname,
                eventdescription: req.body.eventdescription,
                eventtype: req.body.eventtype,
                eventrecurrencepattern: req.body.eventrecurrencepattern
            });

        // Update event
        await knex("event")
            .where("eventid", req.params.id)
            .update({
                eventdatetimestart: req.body.eventdatetimestart,
                eventdatetimeend: req.body.eventdatetimeend,
                eventlocation: req.body.eventlocation,
                eventcapacity: req.body.eventcapacity
            });

        res.redirect("/events");
    } catch (err) {
        console.error("Error saving event edits:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// MANAGER: Delete Event
// -----------------------------------------------------
app.post("/events/delete/:id", requireManager, async (req, res) => {
    try {
        await knex("event")
            .where("eventid", req.params.id)
            .del();

        res.redirect("/events");
    } catch (err) {
        console.error("Error deleting event:", err);
        res.status(500).render("404");
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

