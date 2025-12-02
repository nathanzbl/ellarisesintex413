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

app.post("/survey", async (req, res) => {
  const {
    SurveyEmail,
    SurveyEventId,
    SurveyEventDate,
    SurveySatisfactionScore,
    SurveyUsefulnessScore,
    SurveyInstructorScore,
    SurveyRecommendationScore,

    SurveyComments
  } = req.body;

  try {
    // 1) Look up participant by email using knex.raw
    const emailResult = await knex.raw(
      "SELECT participantid, participantemail FROM participant WHERE participantemail = ?",
      [SurveyEmail]
    );

    // With Postgres, knex.raw returns { rows: [...] }
    const rows = emailResult.rows || emailResult;

    if (!rows || rows.length === 0) {
      // Email not found, reload page with error
      const events = await knex("eventdefinition")
        .select("eventdefid", "eventname")
        .orderBy("eventdefid", "asc");

      return res.status(400).render("surveys", {
        events,
        error_message: "We could not find that email in our records. Please use the email you used to register."
      });
    }

    const participantId = rows[0].participantid;

    // Parse scores to integers
    const sat = Number(SurveySatisfactionScore);
    const useful = Number(SurveyUsefulnessScore);
    const instr = Number(SurveyInstructorScore);
    const recom = Number(SurveyRecommendationScore);

    const overall = Math.round((sat + useful + instr + recom) / 4);

    // 2) Insert into survey table
     await knex("survey").insert({
      participantid: participantId,
      eventid: SurveyEventId,
      recommendationid: recom,            // or whatever id you actually want here
      surveysatisfactionscore: sat,
      surveyusefulnessscore: useful,
      surveyinstructorscore: instr,
      surveyrecommendationscore: recom,
      surveyoverallscore: overall,        // now an int, not 1388.75
      surveycomments: SurveyComments || null,
      surveysubmissiondate: knex.fn.now()
    });

    // 3) Redirect to a thank you page or something similar
    res.redirect("/survey/thankyou");
  } catch (err) {
    console.error("Survey submit error:", err);

    const events = await knex("eventdefinition")
      .select("eventdefid", "eventname")
      .orderBy("eventdefid", "asc");

    res.status(500).render("surveys", {
      events,
      error_message: "There was a problem saving your survey. Please try again."
    });
  }
});

app.get("/survey/thankyou", (req, res) => {
    res.render("surveyThankYou");
}); 

app.get("/survey/responses", async (req, res) => {
  const { eventDefId } = req.query; // query param from the dropdown

  try {
    // Event definitions for the dropdown
    const events = await knex("eventdefinition")
      .select("eventdefid", "eventname")
      .orderBy("eventdefid", "asc");

    // Base query: survey -> event -> eventdefinition -> participant
    let query = knex("survey as s")
      .join("event as e", "e.eventid", "s.eventid")
      .join("eventdefinition as ed", "ed.eventdefid", "e.eventdefid")
      .join("participant as p", "s.participantid", "p.participantid")
      .select(
        "s.surveyid",
        "s.eventid",
        "e.eventdefid",
        "ed.eventname",
        "p.participantemail",
        "s.surveysatisfactionscore",
        "s.surveyusefulnessscore",
        "s.surveyinstructorscore",
        "s.surveyrecommendationscore",
        "s.surveyoverallscore",
        "s.surveycomments",
        "s.surveysubmissiondate"
      )
      .orderBy("s.surveysubmissiondate", "desc");

    // Filter by event definition if one was selected
    if (eventDefId && eventDefId !== "") {
      query = query.where("e.eventdefid", Number(eventDefId));
    }

    const surveys = await query;

    res.render("surveyResponses", {
      surveys,
      events,
      selectedEventDefId: eventDefId || ""
    });
  } catch (err) {
    console.error("Survey responses error:", err);
    res.status(500).send("Error loading survey responses");
  }
});



app.post("/survey/:surveyid/delete", async (req, res) => {
  const { surveyid } = req.params;
  const { eventId } = req.query; // to preserve filter on redirect

  try {
    await knex("survey")
      .where({ surveyid })
      .del();

    const redirectUrl = eventId
      ? `/survey/responses?eventId=${encodeURIComponent(eventId)}`
      : "/survey/responses";

    res.redirect(redirectUrl);
  } catch (err) {
    console.error("Error deleting survey:", err);
    res.status(500).send("Error deleting survey response");
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

// -----------------------------------------------------
// HELPER FUNCTION: Fetch paginated participants
// (Updated to ensure limit and offset are correctly applied)
// -----------------------------------------------------
const fetchAllParticipants = async (limit, offset) => {
    try {
        const participants = await knex("participant")
            .select(
                "participantid",
                "participantfirstname",
                "participantlastname",
                "participantemail",
                "participantphone" 
            )
            // CRITICAL: Apply LIMIT and OFFSET here
            .limit(limit)
            .offset(offset)
            .orderBy("participantid", "asc");
            
        return participants;

    } catch (error) {
        console.error("❌ Database query error in fetchAllParticipants:", error.message);
        // Re-throw the error so the main route can catch it
        throw new Error("Failed to fetch participants from database.");
    }
};

// -----------------------------------------------------
// PARTICIPANT ROUTES
// -----------------------------------------------------

// GET /participants - Display the list of all participants with pagination
app.get('/participants', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.render("login", { error_message: "" });
    }
    // Setup user object for EJS rendering
    const user = req.session.user ? {
        ...req.session.user,
        name: req.session.user.username,
        isManager: req.session.user.role === 'manager'
    } : { username: 'Guest', role: 'guest' };
    
    // Get and clear session message
    const message = req.session.message;
    delete req.session.message;
    
    // --- Pagination Logic (Uses 100 per page) ---
    const limit = 100;
    // Ensure currentPage defaults to 1 and is an integer
    const currentPage = parseInt(req.query.page) > 0 ? parseInt(req.query.page) : 1;
    const offset = (currentPage - 1) * limit;
    let totalParticipants = 0;
    // --------------------------------------------

    try {
        // 1. Get total count for pagination (required to calculate total pages)
        const countResult = await knex('participant').count('* as count');
        totalParticipants = parseInt(countResult[0].count, 10);
        
        // 2. Fetch paginated data (ONLY 100 records for the current page)
        const allParticipants = await fetchAllParticipants(limit, offset); 
        
        console.log(`✅ PARTICIPANT DATA STATUS: Fetched ${allParticipants.length} participants for page ${currentPage} (Total: ${totalParticipants}).`);
        
        // 3. Render View
        const totalPages = Math.ceil(totalParticipants / limit);
        
        res.render('participant/participants', { 
            user: user, 
            participants: allParticipants, 
            searchQuery: '',
            message: message, 
            error_message: null,
            currentPage: currentPage, 
            totalPages: totalPages
        });
        
    } catch (error) {
        console.error("❌ Participant Route Render Error:", error.message);
        // Pass error through render function
        res.render('participant/participants', {
            user: user, 
            participants: [],
            searchQuery: '',
            message: null,
            error_message: error.message,
            currentPage: 1, 
            totalPages: 1
        });
    }
});

// GET /addParticipant - Display the form (Create Form)
app.get("/addParticipant", (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.render("login", { error_message: "" });
    }
    const user = req.session.user ? {
        ...req.session.user,
        name: req.session.user.username,
        isManager: req.session.user.role === 'manager'
    } : { username: 'Guest', role: 'guest' };
    
    // Pass error_message as an empty string to prevent EJS crash
    res.render("participant/addparticipant", { message: null, user: user, error_message: "" });
});

// POST /addParticipant - Handle form submission (Create Action)
app.post("/addParticipant", async (req, res) => {
    // Assuming fields like firstName, lastName, email, etc.
    const { firstName, lastName, email } = req.body; 
    
    const user = req.session.user ? {
        ...req.session.user,
        name: req.session.user.username,
        isManager: req.session.user.role === 'manager'
    } : { username: 'Guest', role: 'guest' };
    
    // Basic Validation
    if (!firstName || !lastName || !email) {
        // Pass validation error via error_message
        return res.status(400).render("participant/addparticipant", { 
            user: user,
            message: null, 
            error_message: "All fields (First Name, Last Name, Email) are required."
        });
    }

    try {
        // Insert new participant into the 'participant' table
        await knex("participant").insert({
            participantfirstname: firstName,
            participantlastname: lastName,
            participantemail: email
            // Add other necessary participant fields here
        });

        // Success: Redirect to the list view
        req.session.message = { type: 'success', text: 'Participant successfully added!' };
        res.redirect("/participants");
    } catch (err) {
        console.error("Error in add Participant process:", err.message);
        
        // Pass database error via error_message
        res.status(500).render("participant/addparticipant", { 
             user: user,
             message: null,
             error_message: "Unable to save Participant. Check for duplicate email or database constraints."
        })
    }
});

// GET /editParticipant/:id - Display the form for a single participant (Read Single/Update Form)
app.get("/editParticipant/:id", (req, res) => {    
    if (!req.session.isLoggedIn) {
        return res.render("login", { error_message: "" });
    }
    const participantId = req.params.id;
    const user = req.session.user ? {
        ...req.session.user,
        name: req.session.user.username,
        isManager: req.session.user.role === 'manager'
    } : { username: 'Guest', role: 'guest' };

    knex("participant")
        .where({ participantid: participantId })
        .first()
        .then((participant) => {
            if (!participant) {
                // Set temporary message in session before redirecting
                req.session.message = { type: 'error', text: `Participant with ID ${participantId} not found.` };
                return res.status(404).redirect("/participants"); 
            }
            // Ensure error_message is passed to edit form
            res.render("participant/editparticipant", { participant, user, error_message: "" }); 
        })
        .catch((err) => {
            console.error("Error fetching participant:", err.message);
            // Fallback render to the list view
             req.session.message = { type: 'error', text: 'Unable to load participant for editing.' };
            res.status(500).redirect("/participants");
        });   
});

// POST /editParticipant/:id - Handle form submission for editing (Update Action)
app.post("/editParticipant/:id", async (req, res) => {
    const participantId = req.params.id;
    const { firstName, lastName, email } = req.body; 
    
    const user = req.session.user ? {
        ...req.session.user,
        name: req.session.user.username,
        isManager: req.session.user.role === 'manager'
    } : { username: 'Guest', role: 'guest' };
    
    // Basic Validation
    if (!firstName || !lastName || !email) { 
        // Need to refetch data to re-render the edit form
        const participant = await knex("participant").where({ participantid: participantId }).first();
        if (!participant) {
            req.session.message = { type: 'error', text: `Participant with ID ${participantId} not found.` };
            return res.status(404).redirect("/participants");
        }

        return res.status(400).render("participant/editparticipant", {
            participant,
            user,
            error_message: "All fields are required."
        });
    }

    // Prepare Update Object
    const updatedParticipant = {
        participantfirstname: firstName,
        participantlastname: lastName,
        participantemail: email
        // Add other necessary participant fields here
    };
    
    try {
        // Run Update Query
        const rowsUpdated = await knex("participant")
            .where({ participantid: participantId }) 
            .update(updatedParticipant);

        if (rowsUpdated === 0) {
            console.warn(`Participant ID ${participantId} not found for update.`);
        }
        
        // Success: Redirect to the list view
        req.session.message = { type: 'success', text: `Participant ID ${participantId} successfully updated!` };
        res.redirect("/participants");
    } catch (err) {
        console.error("Error updating participant:", err.message);
        
        // On update failure, refetch the original participant data and display the error
        const participant = await knex("participant").where({ participantid: participantId }).first();

        res.status(500).render("participant/editparticipant", {
            participant: participant || {}, // Use empty object if refetch failed
            user,
            error_message: "Unable to update participant due to a database error."
        });
    }
});

// POST /deleteParticipant/:id - Delete a participant (Delete Action)
app.post("/deleteParticipant/:id", (req, res) => {
    if (req.session.user.role !== 'manager') {
        req.session.message = { type: 'error', text: 'Authorization denied.' };
        return res.redirect("/participants");
    }
    
    knex("participant")
        .where("participantid", req.params.id)
        .del()
        .then(rowsDeleted => {
            if (rowsDeleted > 0) {
                req.session.message = { type: 'success', text: `Participant ID ${req.params.id} successfully deleted.` };
            } else {
                req.session.message = { type: 'error', text: `Participant ID ${req.params.id} not found.` };
            }
            res.redirect("/participants");
        })
        .catch(err => {
            console.error("Error deleting participant:", err);
            req.session.message = { type: 'error', text: 'A database error prevented the deletion.' };
            res.status(500).redirect("/participants");
        });
});

// delete participant
app.post("/deleteParticipant/:id", (req, res) => {
    knex("participant").where("participantid", req.params.id).del().then(participant => {
        res.redirect("/participants");
    }).catch(err => {
        console.log(err);
        res.status(500).json({err});
    })
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
