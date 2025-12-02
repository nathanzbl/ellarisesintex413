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
    if (req.path === '/' || req.path === '/login' || req.path === '/logout' || req.path === '/donations' || req.path === '/register') {
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
        res.render("surveys" ,{
    error_message: null,          // make sure this always exists
    // any other data you pass in...
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

async function fetchAllParticipants() {
    try {
        const participants = await knex('participant') // <<< CHECK THIS NAME: 'participant'
            .select(
                'participant.participant_id as id',
                'participant.first_name as firstName',
                'participant.last_name as lastName',
                'participant.status as status',
                'program.program_name as currentProgram' // Use 'program' if that's the program table
            )
            // UPDATE: Use the correct junction table name
            .leftJoin('participant_program', 
                      'participant.participant_id', 
                      'participant_program.participant_id')
            
            // UPDATE: Use the correct program table name
            .leftJoin('program', // <<< CHECK THIS NAME: 'program'
                      'participant_program.program_id', 
                      'program.program_id')
            
            .where('participant_program.is_current', true) 
            
            // Ensure GROUP BY uses the correct table names
            .groupBy('participant.participant_id', 'participant.first_name', 'participant.last_name', 'participant.status', 'program.program_name');

        return participants;
    } catch (err) {
        console.error("Database query error in fetchAllParticipants:", err.message);
        return []; 
    }
}

async function searchParticipants(query) {
    let knexQuery = knex('participant') // <<< CHECK THIS NAME: 'participant'
        .select(
            'participant.participant_id as id',
            'participant.first_name as firstName',
            'participant.last_name as lastName',
            'participant.status as status',
            'program.program_name as currentProgram'
        )
        // Apply the same JOINs as above
        .leftJoin('participant_program', 
                  'participant.participant_id', 
                  'participant_program.participant_id')
        .leftJoin('program', 
                  'participant_program.program_id', 
                  'program.program_id')
        .where('participant_program.is_current', true) 
        .groupBy('participant.participant_id', 'participant.first_name', 'participant.last_name', 'participant.status', 'program.program_name'); 

    if (query) {
        const lowerCaseQuery = `%${query.toLowerCase()}%`;
        
        knexQuery.where(builder => {
            // Ensure column names are correct: first_name, last_name, etc.
            builder.whereRaw('LOWER(participant.first_name) LIKE ?', [lowerCaseQuery])
                   .orWhereRaw('LOWER(participant.last_name) LIKE ?', [lowerCaseQuery])
                   .orWhereRaw('LOWER(program.program_name) LIKE ?', [lowerCaseQuery])
                   .orWhereRaw('participant.participant_id::text LIKE ?', [lowerCaseQuery]); 
        });
    }

    try {
        return await knexQuery;
    } catch (err) {
        console.error("Database query error in searchParticipants:", err.message);
        return [];
    }
}

app.get('/participants', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login'); 
    }
    
    req.session.user.name = req.session.user.username;
    req.session.user.isManager = req.session.user.role === 'manager';

    try {
        // Await the asynchronous database function (NEW)
        const allParticipants = await fetchAllParticipants(); 
        
        res.render('participants', { 
            user: req.session.user,
            participants: allParticipants, // Data from DB
            searchQuery: '' 
        });
    } catch (error) {
        console.error("Error rendering participants page:", error);
        res.render('participants', {
            user: req.session.user,
            participants: [],
            searchQuery: '',
            error_message: "Could not load participants data." // Optional error message
        });
    }
});



// GET Route to handle search queries
// index.js

// Updated GET Route to handle search queries
app.get('/participants/search', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    
    // TEMPORARY: (User setup for EJS rendering)
    req.session.user.name = req.session.user.username;
    req.session.user.isManager = req.session.user.role === 'manager';

    const query = req.query.query || '';
    
    try {
        // Await the asynchronous database search function (NEW)
        const filteredParticipants = await searchParticipants(query); 

        res.render('participants', {
            user: req.session.user,
            participants: filteredParticipants,
            searchQuery: query
        });
    } catch (error) {
        console.error("Error rendering search results:", error);
        res.render('participants', {
            user: req.session.user,
            participants: [],
            searchQuery: query,
            error_message: "Could not perform search."
        });
    }
});

// implement once the events and milestone pages have been created
//
// function fetchAllMilestones() {
//     return [
//         { id: 1, participantId: 101, title: 'Completed Level 1 Folklorico', date: '2025-09-01' },
//         { id: 2, participantId: 102, title: 'STEAM Certification (Basic Robotics)', date: '2025-10-20' }
//     ];
// }
//
// app.get('/milestones', (req, res) => {
//     if (!req.session.user) {
//         return res.redirect('/login');
//     }
//     req.session.user.name = req.session.user.username;
//     req.session.user.isManager = req.session.user.role === 'manager';

//     const allMilestones = fetchAllMilestones(); 

//     res.render('milestones', { 
//         user: req.session.user, 
//         milestones: allMilestones,
//         searchQuery: ''
//     });
// });

// app.get('/events', (req, res) => {
//     if (!req.session.user) {
//         return res.redirect('/login'); 
//     }
//     req.session.user.name = req.session.user.username;
//     req.session.user.isManager = req.session.user.role === 'manager';

//     const allEvents = fetchAllEvents(); 

//     res.render('events', { 
//         user: req.session.user, 
//         events: allEvents,
//         searchQuery: ''
//     });
// });

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

app.get("/donations", (req, res) => {
    res.render("donations");
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
            [username, hashedPassword, 'owner']
        );

        console.log(`✅ New owner registered: ${username}`);

        return res.status(200).json({ 
            success: true, 
            message: 'Owner registration successful!', 
            redirectTo: '/login' 
        });

    } catch (error) {
        console.error('Owner registration error:', error);
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

app.get("/teapot", (req, res) => {
    // Teapot response
    res.status(418).render("teapot"); 
});

app.listen(port, () => {
    console.log("The server is listening");
});