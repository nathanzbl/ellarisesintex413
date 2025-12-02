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

// Donation Routes
app.get("/donations", (req, res) => {
    res.render("donations");
});

// Milestone Routes
app.get("/milestones", (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.render("login", { error_message: "" });
    }

    const limit = 100; // Number of items per page
    const currentPage = parseInt(req.query.page) || 1;
    const offset = (currentPage - 1) * limit;

    let totalMilestones = 0;

    knex('milestone')
        .innerJoin(
            'participant', 
            'milestone.participantid', 
            'participant.participantid'
        )
        .count('* as count')
        .then(result => {
            totalMilestones = parseInt(result[0].count);
            
            return knex
                .select(
                    'milestone.*',
                    'participant.participantfirstname', 
                    'participant.participantlastname',
                    'participant.participantemail'
                )
                .from("milestone")
                .innerJoin(
                    'participant', 
                    'milestone.participantid', 
                    'participant.participantid'
                )
                
                .limit(limit)
                .offset(offset);
        })
        .then(milestones => {
            console.log(`Successfully retrieved ${milestones.length} milestones for page ${currentPage}`);
            
            // Calculate total pages needed
            const totalPages = Math.ceil(totalMilestones / limit);
            
            res.render("milestone/milestones", {
                milestone: milestones,
                currentPage: currentPage,
                totalPages: totalPages,
            });
        })
        .catch((err) => {
            console.error("Database query error:", err.message);
            res.render("milestone/milestones", {
                milestone: [],
                currentPage: 1, 
                totalPages: 1,
                error_message: `Database error: ${err.message}. Please check if the 'milestone' table exists.`
            });
        });
});

// Add Milestone Post Route
app.post("/addmilestone", (req, res) => {
    const { milestonetitle, milestonedate } = req.body;
    let { participantIdentifier } = req.body; 
    
    participantIdentifier = participantIdentifier.trim();
    
    // validation check
    if (!milestonetitle || !milestonedate || !participantIdentifier) {
        return res.status(400).render("milestone/addmilestone", { 
            message: { type: "error", text: "Milestone Title, Date, and Participant Identifier are required." }
        });
    }

    let participantIdToInsert;
    let lookupQuery = knex("participant").select("participantid");
    
    // Check if the input is a number (meaning they entered an ID)
    if (!isNaN(parseInt(participantIdentifier))) {
        lookupQuery = lookupQuery.where({
            participantid: parseInt(participantIdentifier)
        });
        console.log(`Looking up participant by ID: ${participantIdentifier}`);
    } else {
        lookupQuery = lookupQuery.where({
            participantemail: participantIdentifier
        });
        console.log(`Looking up participant by Email: ${participantIdentifier}`);
    }
    
    // Execute the built query
    lookupQuery.first() 
        .then((participant) => {
            if (!participant) {
                throw new Error(`Participant identifier "${participantIdentifier}" not found. Please verify the ID or Email.`);
            }
            
            // Store the unique ID
            participantIdToInsert = participant.participantid;

            const newMilestone = {
                milestonetitle,
                milestonedate,
                participantid: participantIdToInsert
            };

            // Return the insert query to continue the promise chain
            return knex("milestone").insert(newMilestone);
        })
        .then(() => {
            // Success: Insertion complete
            res.redirect("/milestones");
        })
        .catch((err) => {
            // Error handling
            let errorMessage = "Unable to save Milestone. Please try again.";
            
            if (err.message.includes("Participant identifier")) {
                errorMessage = err.message;
            } else {
                console.error("Error in add Milestone process:", err.message);
            }

            res.status(500).render("addmilestone", { 
                 message: { type: "error", text: errorMessage }
            });
        });
});

// add milestone get route
app.get("/addMilestone", (req, res) => {
    if (req.session.isLoggedIn) {
        res.render("milestone/addmilestone");
    }
    else {
        res.render("login", { error_message: "" });
    }  
});

// edit milestone get route
app.get("/editMilestone/:id", (req, res) => {    
    const milestoneId = req.params.id;
    knex("milestone")
        .where({ milestoneid: milestoneId })
        .first()
        .then((milestone) => {
            if (!milestone) {
                return res.status(404).render("/milestones", {
                    milestone: [],
                    error_message: "Milestone not found."
                });
            }
            res.render("editmilestone", { user, error_message: "" });
        })
        .catch((err) => {
            console.error("Error fetching milestone:", err.message);
            res.status(500).render("milestone/milestones", {
                workshops: [],
                error_message: "Unable to load milestone for editing."
            });
        });   
});

// Edit Milestone POST Route
app.post("/editMilestone/:id", (req, res) => {
    const milestoneID = req.params.id;
    
    const { milestonetitle, milestonedate } = req.body; 
    
    if (!milestonetitle || !milestonedate) { 
        return knex("milestone")
            .where({ milestoneid: milestoneID }) 
            .first()
            .then((milestone) => {
                if (!milestone) {
                    return res.status(404).render("milestone_list", {
                        milestones: [],
                        error_message: "Milestone not found for validation."
                    });
                }
                // Render the edit form again with an error message
                res.status(400).render("milestone/editmilestone", {
                    milestone,
                    error_message: "Milestone Title and Date are required."
                });
            })
            .catch((err) => {
                console.error("Error fetching milestone for validation fail:", err.message);
                res.status(500).render("milestone_list", {
                    milestones: [],
                    error_message: "Unable to load milestone for editing."
                });
            });
    }

    // --- Prepare Update Object ---
    const updatedMilestone = {
        milestonetitle,
        milestonedate
    };
    
    // --- Run Update Query ---
    knex("milestone")
        .where({ milestoneid: milestoneID }) // Target the specific milestone
        .update(updatedMilestone)
        .then((rowsUpdated) => {
            if (rowsUpdated === 0) {
                // If 0 rows were updated, the ID was likely invalid or not found
                return res.status(404).render("milestone_list", {
                    milestones: [],
                    error_message: `Milestone with ID ${milestoneID} not found or no changes were made.`
                });
            }
            // Success: Redirect to the list view
            res.redirect("/milestones");
        })
        .catch((err) => {
            console.error("Error updating milestone:", err.message);
            
            // On update failure, refetch the original milestone data and display the error
            knex("milestone")
                .where({ milestoneid: milestoneID })
                .first()
                .then((milestone) => {
                    if (!milestone) {
                        return res.status(404).render("milestone_list", {
                            milestones: [],
                            error_message: "Milestone not found after update failure."
                        });
                    }
                    // Render the edit form with the database error message
                    res.status(500).render("editMilestone", {
                        milestone,
                        error_message: "Unable to update milestone due to a database error. Please check your data."
                    });
                })
                .catch((fetchErr) => {
                    console.error("Error fetching milestone after update failure:", fetchErr.message);
                    res.status(500).render("milestone_list", {
                        milestones: [],
                        error_message: "A critical error occurred. Cannot update milestone."
                    });
                });
        });
})


// delete milestone
app.post("/deleteMilestone/:id", (req, res) => {
    knex("milestone").where("milestoneid", req.params.id).del().then(milestone => {
        res.redirect("/milestones");
    }).catch(err => {
        console.log(err);
        res.status(500).json({err});
    })
});

// Participant Routes
app.get("/participants", (req, res) => {
    res.render("participants");
});

// Events Routes
app.get("/events", (req, res) => {
    res.render("events");
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

app.listen(port, () => {
    console.log("The server is listening");
});