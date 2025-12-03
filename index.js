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

app.use(
    session(
        {
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
        }
    )
);

// session middleware
function setViewGlobals(req, res, next) {
    // Check if req.session.isLoggedIn is defined; if so, pass it to the views.
    // If not logged in, isLoggedIn will be false or undefined, which EJS can check.
    res.locals.isLoggedIn = req.session.isLoggedIn || false; 
    
    // Continue to the next middleware or route handler
    next(); 
}

// Then, tell Express to use this function for all requests:
app.use(setViewGlobals);


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
  const { eventDefId } = req.query;
  const pageSize = 25;
  const rawPage = parseInt(req.query.page, 10) || 1;
  const page = Math.max(rawPage, 1);

  try {
    // Event definitions for the dropdown
    const events = await knex("eventdefinition")
      .select("eventdefid", "eventname")
      .orderBy("eventdefid", "asc");

    // Base query
    let baseQuery = knex("survey as s")
      .join("event as e", "e.eventid", "s.eventid")
      .join("eventdefinition as ed", "ed.eventdefid", "e.eventdefid")
      .join("participant as p", "s.participantid", "p.participantid");

    if (eventDefId && eventDefId !== "") {
      baseQuery = baseQuery.where("e.eventdefid", Number(eventDefId));
    }

    // Count
    const countRow = await baseQuery
      .clone()
      .countDistinct({ total: "s.surveyid" })
      .first();

    const totalCount = parseInt(countRow.total, 10) || 0;
    const totalPages = totalCount === 0 ? 1 : Math.ceil(totalCount / pageSize);
    const currentPage = Math.min(page, totalPages);
    const offset = (currentPage - 1) * pageSize;

    // Data
    const surveys = await baseQuery
      .clone()
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
      .orderBy("s.surveysubmissiondate", "desc")
      .limit(pageSize)
      .offset(offset);

    const firstItem = totalCount === 0 ? 0 : offset + 1;
    const lastItem = offset + surveys.length;

    // Sliding window: 10 pages at a time
    const windowSize = 10;
    const windowStart =
      Math.floor((currentPage - 1) / windowSize) * windowSize + 1;
    const windowEnd = Math.min(windowStart + windowSize - 1, totalPages);

    res.render("surveyResponses", {
      surveys,
      events,
      selectedEventDefId: eventDefId || "",
      pagination: {
        currentPage,
        totalPages,
        totalCount,
        pageSize,
        firstItem,
        lastItem,
        windowSize,
        windowStart,
        windowEnd
      }
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

app.get("/survey/:surveyid/edit", async (req, res) => {
  const { surveyid } = req.params;
  const { eventDefId } = req.query;

  try {
    const survey = await knex("survey as s")
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
      .where("s.surveyid", surveyid)
      .first();

    if (!survey) {
      return res.status(404).send("Survey response not found");
    }

    res.render("surveyEdit", {
      survey,
      eventDefId: eventDefId || ""
    });
  } catch (err) {
    console.error("Survey edit load error:", err);
    res.status(500).send("Error loading survey for edit");
  }
});

app.post("/survey/:surveyid/edit", async (req, res) => {
  const { surveyid } = req.params;
  const { eventDefId } = req.query;

  const {
    SurveySatisfactionScore,
    SurveyUsefulnessScore,
    SurveyInstructorScore,
    SurveyRecommendationScore,
    SurveyComments
  } = req.body;

  try {
    const sat = Number(SurveySatisfactionScore);
    const useful = Number(SurveyUsefulnessScore);
    const instr = Number(SurveyInstructorScore);
    const recom = Number(SurveyRecommendationScore);

    // Basic sanity check if you want to be strict
    // if ([sat, useful, instr, recom].some(n => !Number.isInteger(n) || n < 1 || n > 5)) { ... }

    const overall = Math.round((sat + useful + instr + recom) / 4);

    await knex("survey")
      .where({ surveyid })
      .update({
        surveysatisfactionscore: sat,
        surveyusefulnessscore: useful,
        surveyinstructorscore: instr,
        surveyrecommendationscore: recom,
        surveyoverallscore: overall,
        surveycomments: SurveyComments || null
      });

    const redirectUrl = eventDefId
      ? `/survey/responses?eventDefId=${encodeURIComponent(eventDefId)}`
      : "/survey/responses";

    res.redirect(redirectUrl);
  } catch (err) {
    console.error("Survey edit save error:", err);
    res.status(500).send("Error saving survey changes");
  }
});

app.post("/donations/add", async (req, res, next) => {
  try {
    const {
      first_name,
      last_name,
      email,
      phone,
      amount_choice,
      other_amount,
      frequency,
      designation,
      note,
      anonymous,
      updates,
    } = req.body;

    // Basic required field checks
    if (!first_name || !last_name || !email || !phone) {
      return res.status(400).render("donations", {
        error_message: "First name, last name, email, and phone are required.",
      });
    }

    // 1. Figure out the actual donation amount
    let donationAmount = 0;

    const other = Number(other_amount);
    const preset = Number(amount_choice);

    if (!isNaN(other) && other > 0) {
      donationAmount = other;
    } else if (!isNaN(preset) && preset > 0) {
      donationAmount = preset;
    }

    const isAnonymous = !!anonymous;
     const ANONYMOUS_PARTICIPANT_ID = 1182;



     
    if (!donationAmount || donationAmount <= 0) {
      return res.status(400).render("donations", {
        error_message: "Please choose or enter a valid donation amount.",
      });
    }

    // 2. Look up participant by email
    let participant = await knex("participant")
      .where({ participantemail: email })
      .first();

    let participantId;
    let newTotalDonations;

    if (isAnonymous) {
      // Anonymous - donations tied to the anonymous participant row
      participantIdForDonation = ANONYMOUS_PARTICIPANT_ID;
      participantIdForTotals = ANONYMOUS_PARTICIPANT_ID;

      // Update totaldonations on the anonymous row
      const anon = await knex("participant")
        .where({ participantid: ANONYMOUS_PARTICIPANT_ID })
        .first();

      const currentTotalAnon = anon && anon.totaldonations
        ? Number(anon.totaldonations)
        : 0;

      const newTotalAnon = currentTotalAnon + donationAmount;

      await knex("participant")
        .where({ participantid: ANONYMOUS_PARTICIPANT_ID })
        .update({
          totaldonations: newTotalAnon,
        });

      // Notice: we are not creating/updating a personal participant row
      // for the donor when they choose to be anonymous.
    }

    if (!participant) {
      // New participant, phone required here
      const [inserted] = await knex("participant")
        .insert({
          participantfirstname: cap(first_name),
          participantlastname: cap(last_name),
          participantemail: email,
          participantphone: phone,               // now required
          participantrole: "participant",
          totaldonations: donationAmount,
        })
        .returning(["participantid", "totaldonations"]);

      participantId = inserted.participantid;
      newTotalDonations = inserted.totaldonations;
    } else {
      participantId = participant.participantid;
      const currentTotal = Number(participant.totaldonations) || 0;
      newTotalDonations = currentTotal + donationAmount;

      await knex("participant")
        .where({ participantid: participantId })
        .update({
          totaldonations: newTotalDonations,
          // Optionally refresh phone if they changed it:
          participantphone: phone,
        });
    }

    // 4. Calculate donationnumber
    const countRow = await knex("donation")
      .where({ participantid: participantId })
      .count("* as count")
      .first();

    const previousCount = Number(countRow.count) || 0;
    const donationNumber = previousCount + 1;

    // 5. Insert into donations
    await knex("donation").insert({
      participantid: participantId,
      donationnumber: donationNumber,
      donationamount: donationAmount,
      donationdate: new Date(),
      isanonymous: isAnonymous

    });

    res.redirect("/donations/thank-you");
  } catch (err) {
    console.error("Donation error:", err);
    next(err);
  }
});

app.get("/donations/thank-you", (req, res) => { 
    res.render("donationThankYou");
});



// GET /donations
app.get('/donations/view', async (req, res) => {
  try {
    // RBAC here if you want
    // if (!req.user || !req.user.isadmin) return res.status(403).render('403');

    const pageSize = 25;
    const currentPage = Number(req.query.page) > 0 ? Number(req.query.page) : 1;

    const {
      participantSearch,
      eventSearch,
      minAmount,
      maxAmount
    } = req.query;

    // Base query with Participant + PrimaryKey + Event + EventDefinition
    const baseQuery = knex('donation as d')
      .leftJoin('participant as p', 'd.participantid', 'p.participantid')
      .leftJoin('primarykey as pk', 'd.donationid', 'pk.donationid')
      .leftJoin('event as ev', 'pk.eventid', 'ev.eventid')
      .leftJoin('eventdefinition as ed', 'ev.eventdefid', 'ed.eventdefid');

    const applyFilters = (q) => {
      if (participantSearch && participantSearch.trim() !== '') {
        const term = participantSearch.trim();
        q.where(function () {
          this.whereILike('p.participantfirstname', `%${term}%`)
            .orWhereILike('p.participantlastname', `%${term}%`)
            .orWhereILike('p.participantemail', `%${term}%`);
        });
      }

      if (eventSearch && eventSearch.trim() !== '') {
        q.whereILike('ed.eventname', `%${eventSearch.trim()}%`);
      }

      if (minAmount && minAmount !== '') {
        q.where('d.donationamount', '>=', Number(minAmount));
      }

      if (maxAmount && maxAmount !== '') {
        q.where('d.donationamount', '<=', Number(maxAmount));
      }
    };

    // Count query
    const countQuery = baseQuery.clone();
    applyFilters(countQuery);

    const countResult = await countQuery.countDistinct({ total: 'd.donationid' });
    const totalRows = Number(countResult[0].total || 0);
    const totalPages = totalRows === 0 ? 1 : Math.ceil(totalRows / pageSize);

    const safePage =
      currentPage > totalPages ? totalPages : currentPage < 1 ? 1 : currentPage;

    // Data query
    const dataQuery = baseQuery.clone();
    applyFilters(dataQuery);

    const donations = await dataQuery
      .select(
        'd.donationid',
        'd.donationnumber',
        'd.donationamount',
        'd.donationdate',
        'p.participantemail',
        'ed.eventname as eventname',
        knex.raw(
          "coalesce(p.participantfirstname, '') || " +
          "case when p.participantfirstname is not null and p.participantlastname is not null then ' ' else '' end || " +
          "coalesce(p.participantlastname, '') as participantname"
        )
      )
      .orderBy('d.donationdate', 'desc')
      .limit(pageSize)
      .offset((safePage - 1) * pageSize);

    res.render('viewDonations', {
      donations,
      participantSearch: participantSearch || '',
      eventSearch: eventSearch || '',
      minAmount: minAmount || '',
      maxAmount: maxAmount || '',
      currentPage: safePage,
      totalPages
    });
  } catch (err) {
    console.error('Error loading donations:', err);
    res.status(500).send('Error loading donations');
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
    res.render("landing");
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

    const limit = 100;
    const currentPage = parseInt(req.query.page) || 1;
    const offset = (currentPage - 1) * limit;

    // --- Search Parameters ---
    const { search_name, search_milestone, date } = req.query;

    let totalMilestones = 0;

    // Base query setup for COUNT and DATA queries
    const createBaseQuery = () => {
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
            );
    };
    
    // Function to apply filtering logic to the query builder
    const applyFilters = (queryBuilder) => {
        
        // Use a single top-level WHERE clause to contain all filters
        queryBuilder.where(function() {
            const builder = this; // Alias for the Knex query builder
            let firstCondition = true; // Flag to manage the initial WHERE/AND

            // --- 1. Participant Name Filter (OR logic for first/last name) ---
            if (search_name) {
                const wildCardSearch = `%${search_name.toLowerCase()}%`;
                
                // Nest the OR block inside a WHERE
                builder.where(function() {
                    this.whereRaw('LOWER(participant.participantfirstname) LIKE ?', [wildCardSearch])
                        .orWhereRaw('LOWER(participant.participantlastname) LIKE ?', [wildCardSearch]);
                });
                firstCondition = false;
            }

            // --- 2. Milestone Title Filter (AND condition) ---
            if (search_milestone) {
                const wildCardSearch = `%${search_milestone.toLowerCase()}%`;
                
                if (firstCondition) {
                    builder.whereRaw('LOWER(milestonetitle) LIKE ?', [wildCardSearch]);
                    firstCondition = false;
                } else {
                    // Use AND if a previous condition (like search_name) was set
                    builder.andWhereRaw('LOWER(milestonetitle) LIKE ?', [wildCardSearch]);
                }
            }

            // --- 3. Date Filter (To Date, AND condition) ---
            if (date) {
                if (firstCondition) {
                    builder.where('milestonedate', '<=', date);
                } else {
                    // Use AND if any previous condition was set
                    builder.andWhere('milestonedate', '<=', date);
                }
            }
        });
        
        return queryBuilder;
    };


    // Step 1: Count the total number of records that match the search filter
    let countQuery = knex('milestone')
        .innerJoin(
            'participant', 
            'milestone.participantid', 
            'participant.participantid'
        );
    
    // Apply filters to the base query
    countQuery = applyFilters(countQuery);

    // Execute count query
    countQuery.count('* as count')
    .then(result => {
        totalMilestones = parseInt(result[0].count);
        
        // Step 2: Build the main data query
        let dataQuery = createBaseQuery();

        // Apply the exact same search filters to the data query
        dataQuery = applyFilters(dataQuery);

        // Apply pagination limits to the filtered results
        return dataQuery
            .limit(limit)
            .offset(offset);
    })
    .then(milestones => {
        console.log(`Successfully retrieved ${milestones.length} milestones for page ${currentPage}. Total filtered: ${totalMilestones}`);
        
        const totalPages = Math.ceil(totalMilestones / limit);
        
        // Render the view, passing back the search terms for sticky fields
        res.render("milestone/milestones", {
            milestone: milestones,
            currentPage: currentPage,
            totalPages: totalPages,
            // Pass search terms back to the view
            search_name,
            search_milestone,
            date
        });
    })
    .catch((err) => {
        console.error("Database query error:", err.message);
        res.render("milestone/milestones", {
            milestone: [],
            currentPage: 1, 
            totalPages: 1,
            error_message: `Database error: ${err.message}.`
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

            res.status(500).render("milestone/addmilestone", { 
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

// GET /participants - Display the list of all participants with pagination and search
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
    
    // --- Pagination Logic ---
    const limit = 100;
    const currentPage = parseInt(req.query.page) > 0 ? parseInt(req.query.page) : 1;
    const offset = (currentPage - 1) * limit;
    let totalParticipants = 0;
    
    // --- Search Parameters ---
    // Extract search parameters from the URL query
    const { search_name, search_id, search_email, search_phone } = req.query; 

    // Function to apply filtering logic to the query builder (used for both count and data)
    const applyFilters = (queryBuilder) => {
        queryBuilder.where(function() {
            const builder = this;
            let firstCondition = true;

            // Helper to determine if we use WHERE (first) or ANDWHERE (subsequent)
            const chainCondition = (conditionFunc) => {
                if (firstCondition) {
                    builder.where(conditionFunc);
                    firstCondition = false;
                } else {
                    builder.andWhere(conditionFunc);
                }
            };
            
            // 1. Participant Name Filter (First Name OR Last Name)
            if (search_name) {
                const wildCardSearch = `%${search_name.toLowerCase()}%`;
                
                chainCondition(function() {
                    this.whereRaw('LOWER(participantfirstname) LIKE ?', [wildCardSearch])
                        .orWhereRaw('LOWER(participantlastname) LIKE ?', [wildCardSearch]);
                });
            }

            // 2. Participant ID Filter
            if (search_id) {
                // If it's a number, treat as exact. Otherwise, use LIKE for partial string search.
                chainCondition(function() {
                    if (!isNaN(parseInt(search_id))) {
                        this.where('participantid', parseInt(search_id));
                    } else {
                         const wildCardSearch = `%${search_id}%`;
                         this.where('participantid', 'LIKE', wildCardSearch);
                    }
                });
            }
            
            // 3. Participant Email Filter
            if (search_email) {
                const wildCardSearch = `%${search_email.toLowerCase()}%`;

                chainCondition(function() {
                    this.whereRaw('LOWER(participantemail) LIKE ?', [wildCardSearch]);
                });
            }
            
            // 4. Participant Phone Filter
            if (search_phone) {
                const wildCardSearch = `%${search_phone}%`;

                chainCondition(function() {
                    // Note: Phone numbers are often stored as strings and searched using LIKE
                    this.where('participantphone', 'LIKE', wildCardSearch);
                });
            }
        });
        
        return queryBuilder;
    };


    try {
        // --- 1. Get total count for pagination ---
        let countQuery = knex('participant').clone();
        countQuery = applyFilters(countQuery);
        
        const countResult = await countQuery.count('* as count');
        totalParticipants = parseInt(countResult[0].count, 10);
        
        // --- 2. Fetch paginated data ---
        let dataQuery = knex.select('*').from('participant');
        dataQuery = applyFilters(dataQuery);
        
        // Apply pagination limits to the filtered results
        const allParticipants = await dataQuery
            .limit(limit)
            .offset(offset);
        
        console.log(`PARTICIPANT DATA STATUS: Fetched ${allParticipants.length} participants for page ${currentPage} (Total: ${totalParticipants}).`);
        
        // --- 3. Render View ---
        const totalPages = Math.ceil(totalParticipants / limit);
        
        res.render('participant/participants', { 
            user: user, 
            participants: allParticipants, 
            message: message, 
            error_message: null,
            currentPage: currentPage, 
            totalPages: totalPages,
            // Pass search parameters back to EJS for sticky fields
            search_name,
            search_id,
            search_email,
            search_phone
        });
        
    } catch (error) {
        console.error("Participant Route Render Error:", error.message);
        
        // Ensure search params stick even on error
        res.render('participant/participants', {
            user: user, 
            participants: [],
            message: null,
            error_message: error.message,
            currentPage: 1, 
            totalPages: 1,
            search_name: req.query.search_name, 
            search_id: req.query.search_id,
            search_email: req.query.search_email,
            search_phone: req.query.search_phone
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

// GET /editParticipant/:id - Display the Participant Profile/Edit Form
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

    // *** FIX: Use Promise.all to fetch both participant data and milestones ***
    Promise.all([
        // 1. Fetch Participant Details
        knex("participant").where({ participantid: participantId }).first(),

        // 2. NEW MILESTONE QUERY: Query the 'milestone' table directly using the participantId
        knex("milestone")
            .select(
                "milestonetitle", // Matches the new table schema
                "milestonedate"   // Matches the new table schema
            )
            .where({ participantid: participantId })
            .orderBy("milestonedate", "desc") // Sort by date for better viewing
    ])
    .then(([participant, milestones]) => { // Destructure results
        if (!participant) {
            req.session.message = { type: 'error', text: `Participant with ID ${participantId} not found.` };
            return res.status(404).redirect("/participants"); 
        }
        
        // Pass the corrected data to the EJS template
        res.render("participant/editparticipant", { 
            participant, 
            milestones, // <-- This array now contains { milestonetitle, milestonedate }
            user, 
            error_message: "" 
        }); 
    })
    .catch((err) => {
        // Log the error so you can see if the Knex query is failing
        console.error("Error fetching participant and milestones:", err.message); 
        
        req.session.message = { type: 'error', text: 'Unable to load participant profile.' };
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
// ADD EVENT FOR A SPECIFIC DAY (from calendar modal)
// MUST COME BEFORE ANY /events/:eventdefid ROUTES
// -----------------------------------------------------
app.post("/events/:eventdefid/day/:date/add", requireManager, async (req, res) => {
    const { eventdefid, date } = req.params;

    try {
        const startDateTime = `${date}T${req.body.starttime}:00`;
        const endDateTime = `${date}T${req.body.endtime}:00`;

        await knex("event").insert({
            eventdefid: eventdefid,
            eventdatetimestart: startDateTime,
            eventdatetimeend: endDateTime,
            eventlocation: req.body.eventlocation,
            eventcapacity: req.body.eventcapacity
        });

        res.redirect(`/events/${eventdefid}`);
    } catch (err) {
        console.error("Error adding event on selected date:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// ADD EVENT (MANUAL ADD EVENT FORM)
// -----------------------------------------------------

// Show Add Event Form
app.get("/events/add", requireManager, (req, res) => {
    res.render("events/addevent", { error_message: "" });
});

// Submit Add Event
app.post("/events/add", requireManager, async (req, res) => {
    try {
        const [def] = await knex("eventdefinition")
            .insert({
                eventname: req.body.eventname,
                eventdescription: req.body.eventdescription,
                eventtype: req.body.eventtype,
                eventrecurrencepattern: req.body.eventrecurrencepattern
            })
            .returning("eventdefid");

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
        res.render("events/addevent", { error_message: "Error adding event." });
    }
});

// -----------------------------------------------------
// EVENT LIST (UNIQUE EVENT TYPES)
// -----------------------------------------------------
app.get("/events", requireManager, async (req, res) => {
    try {
        const eventDefs = await knex("eventdefinition")
            .select("eventdefid", "eventname", "eventdescription")
            .orderBy("eventname");

        res.render("events/eventlist", { eventDefs });
    } catch (err) {
        console.error("Error loading event definitions:", err);
        res.render("events/eventlist", { eventDefs: [] });
    }
});

// -----------------------------------------------------
// EVENT DETAILS FOR A SPECIFIC DAY
// -----------------------------------------------------
app.get("/events/:eventdefid/day/:date", requireManager, async (req, res) => {
    const { eventdefid, date } = req.params;

    let events = await knex("event")
        .join("eventdefinition", "event.eventdefid", "eventdefinition.eventdefid")
        .select("event.*", "eventdefinition.eventname", "eventdefinition.eventdescription")
        .where("event.eventdefid", eventdefid)
        .whereRaw("DATE(eventdatetimestart AT TIME ZONE 'UTC' AT TIME ZONE 'America/Denver') = ?", [date]);

    const dateFormatted = new Date(date).toLocaleDateString("en-US", {
        month: "short", day: "numeric", year: "numeric"
    });

    events = events.map(ev => ({
        ...ev,
        startTimeFormatted: new Date(ev.eventdatetimestart).toLocaleTimeString([], {
            hour: "numeric", minute: "2-digit"
        }),
        endTimeFormatted: new Date(ev.eventdatetimeend).toLocaleTimeString([], {
            hour: "numeric", minute: "2-digit"
        })
    }));

    res.render("events/eventdetails", { events, dateFormatted });
});

// -----------------------------------------------------
// EVENT CALENDAR PAGE
// -----------------------------------------------------
app.get("/events/:eventdefid", requireManager, async (req, res) => {
    try {
        const eventDef = await knex("eventdefinition")
            .where("eventdefid", req.params.eventdefid)
            .first();

        const events = await knex("event")
            .where("eventdefid", req.params.eventdefid)
            .select("eventid", "eventdatetimestart");

        console.log("EVENTDEFID:", req.params.eventdefid);
        console.log("RAW EVENTS:", events);
        events.forEach(ev => console.log(" - eventdatetimestart:", ev.eventdatetimestart));

        const datesAvailable = events.map(ev => {
            const d = new Date(ev.eventdatetimestart);
            const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
            return local.toISOString().split("T")[0];
        });

        res.render("events/eventcalendar", { eventDef, datesAvailable });
    } catch (err) {
        console.error("Error loading calendar:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// EDIT EVENT
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

        res.render("events/editevent", { event });
    } catch (err) {
        console.error("Error loading edit event:", err);
        res.status(500).render("404");
    }
});

// Submit edit
app.post("/events/edit/:id", requireManager, async (req, res) => {
    try {
        const event = await knex("event")
            .where("eventid", req.params.id)
            .first();

        await knex("eventdefinition")
            .where("eventdefid", event.eventdefid)
            .update({
                eventname: req.body.eventname,
                eventdescription: req.body.eventdescription,
                eventtype: req.body.eventtype,
                eventrecurrencepattern: req.body.eventrecurrencepattern
            });

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
        console.error("Error updating event:", err);
        res.status(500).render("404");
    }
});

// -----------------------------------------------------
// DELETE EVENT
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

