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

function cap(s) {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

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
