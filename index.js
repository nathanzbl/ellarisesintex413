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

const nodemailer = require("nodemailer");
const { MailtrapTransport } = require("mailtrap");

const mailtrapClient = nodemailer.createTransport(
  MailtrapTransport({
    token: process.env.MAILTRAP_TOKEN, // put your token in .env
  })
);

const mailSender = {
  address: "hello@byuisresearch.com",
  name: "Ella Rises",
};



const surveyEmailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,                  // e.g. smtp.office365.com
  port: Number(process.env.SMTP_PORT) || 587,   // 587 for TLS
  secure: false,                                // false for 587
  auth: {
    user: process.env.SMTP_USER,                // your Outlook or other SMTP user
    pass: process.env.SMTP_PASS,                // password or API key
  },
});

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
    // 1. Pass isLoggedIn status globally
    res.locals.isLoggedIn = req.session.isLoggedIn || false;

    // 2. Pass the user object globally, providing a safe fallback if no session user exists
    if (req.session.user) {
        // Pass the full user object from the session
        res.locals.user = req.session.user;
        // Pass the user role separately for easy access in views
        res.locals.userRole = req.session.user.role;
    } else {
        // Provide a default/fallback user object to prevent 'user is not defined' errors
        res.locals.user = { username: 'Guest', role: 'guest' };
        res.locals.userRole = 'guest';
    }

    next();
}
// Then, tell Express to use this function for all requests:
app.use(setViewGlobals);

// Helper function to capitalize the first character of a string
function cap(str) {
    if (!str) return str;
    return str.charAt(0).toUpperCase() + str.slice(1);
}
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

app.use((req, res, next) => {
    res.locals.currentUser = req.session.user || null;
    res.locals.isLoggedIn = !!req.session.user;
    next();
});

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

    // PUBLIC ROUTES: no login required
    if (
        req.path === '/' ||
        req.path === '/login' ||
        req.path === '/logout' ||
        req.path === '/donations' ||
        req.path === '/donations/new' ||
        req.path === '/donations/add' ||
        req.path === '/donations/thank-you' ||
        req.path === '/register' ||
        req.path === '/teapot' ||
        req.path.startsWith('/eventspublic') ||
        req.path.startsWith('/events/detail') ||
        req.path.startsWith('/events/rsvp')
    ) {
        return next();
    }

    // Check if user is logged in
    if (!req.session.isLoggedIn) {
        // Save the intended destination path to the session before redirecting to login
        req.session.redirectTo = req.originalUrl;
        return res.render("login", { error_message: "Please log in to access this page" });
    }

    // User is logged in - now check role-based permissions
    const userRole = req.session.user ? req.session.user.role : null;

    // ROLE-BASED ACCESS CONTROL
    // Milestones and Participants require 'viewer' or 'manager' role
    if (req.path.startsWith('/milestones') || req.path.startsWith('/participants')) {
        if (userRole !== 'viewer' && userRole !== 'manager') {
            return res.status(403).render("403");
        }
    }

    // User has appropriate permissions
    return next();
});

app.get('/profile_dashboard', async (req, res) => {
    try {
        // Check if the user is logged in using the global variable set by setViewGlobals
        if (!res.locals.isLoggedIn) {
            // Instead of flashing an error, just redirect or render the 403 page
            // We'll redirect to login, as that's the standard action.
            return res.redirect('/login'); 
            // OR if you prefer to show an error page:
            // return res.status(403).render("403"); 
        }

        // 1. Get the current user's ID from the session
        const currentUserId = req.session.user.id;

        // 2. Fetch the user's detailed data from the database
        const user = await knex("users")
            .where("participantid", currentUserId)
            .first();

        if (!user) {
            // If user is not found, redirect to login without flashing a message
            return res.redirect('/login');
        }

        // 3. Fetch the participant data
        // Check if a specific participantID was requested via query parameter (for testing)
        const requestedParticipantId = req.query.participantId || user.participantid;

        const participant = await knex("participant")
            .where("participantid", requestedParticipantId)
            .first();

        // 4. Render the profile_dashboard.ejs file and pass both user and participant data
        res.render('profile_dashboard', {
            currentUser: user, // Pass the user account data
            participant: participant || null, // Pass the participant profile data
            requestedParticipantId: requestedParticipantId, // Pass the requested ID for the form
            pageTitle: 'My Profile Dashboard'
        });

    } catch (e) {
        console.error('Error fetching profile dashboard:', e);
        // On error, redirect to the home page without flashing a message
        res.redirect('/');
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

// Helper function to fetch events data for survey form
async function getSurveyEventsData() {
  const eventDefinitions = await knex("eventdefinition")
    .select("eventdefid", "eventname")
    .orderBy("eventname");

  const eventsData = {};
  for (const eventDef of eventDefinitions) {
    const recentDates = await knex("event")
      .where("eventdefid", eventDef.eventdefid)
      .select("eventid", "eventdatetimestart")
      .orderBy("eventdatetimestart", "desc")
      .limit(5);

    if (recentDates.length > 0) {
      eventsData[eventDef.eventdefid] = recentDates.map(evt => ({
        eventid: evt.eventid,
        eventdatetimestart: evt.eventdatetimestart,
        displayDate: new Date(evt.eventdatetimestart).toLocaleDateString("en-US", {
          year: "numeric",
          month: "short",
          day: "numeric"
        })
      }));
    }
  }

  return { eventDefinitions, eventsData };
}

app.get("/surveys", async (req, res) => {
    // Check if user is logged in
    if (req.session.isLoggedIn) {
        try {
            const surveyData = await getSurveyEventsData();
            res.render("survey/surveys", {
                ...surveyData,
                error_message: null
            });
        } catch (err) {
            console.error("Database query error:", err.message);
            res.render("survey/surveys", {
                eventDefinitions: [],
                eventsData: {},
                error_message: `Database error: ${err.message}`
            });
        }
    }
    else {
        res.render("login", { error_message: "" });
    }
});

app.post("/survey", async (req, res) => {
  const {
    SurveyEmail,
    SurveyEventId,
    SurveySatisfactionScore,
    SurveyUsefulnessScore,
    SurveyInstructorScore,
    SurveyRecommendationScore,
    SurveyComments,
  } = req.body;

  try {
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!SurveyEmail || !emailRegex.test(SurveyEmail)) {
      const surveyData = await getSurveyEventsData();
      return res.status(400).render("survey/surveys", {
        ...surveyData,
        error_message: "Please enter a valid email address (e.g., name@example.com).",
      });
    }

    // Validate event selection
    if (!SurveyEventId) {
      const surveyData = await getSurveyEventsData();
      return res.status(400).render("survey/surveys", {
        ...surveyData,
        error_message: "Please select an event from the dropdown.",
      });
    }

    // 1) Look up participant by email
    const emailResult = await knex.raw(
      "SELECT participantid, participantemail FROM participant WHERE LOWER(participantemail) = LOWER(?)",
      [SurveyEmail.trim()]
    );

    const rows = emailResult.rows || emailResult;
    if (!rows || rows.length === 0) {
      const surveyData = await getSurveyEventsData();
      return res.status(400).render("survey/surveys", {
        ...surveyData,
        error_message:
          "We could not find that email in our records. Please use the email you used to register.",
      });
    }

    const participantId = rows[0].participantid;
    const eventId = SurveyEventId;

    // Parse scores
    const sat = Number(SurveySatisfactionScore);
    const useful = Number(SurveyUsefulnessScore);
    const instr = Number(SurveyInstructorScore);
    const recom = Number(SurveyRecommendationScore);
    const overall = Math.round((sat + useful + instr + recom) / 4);

    // 3) Insert into survey
    await knex("survey").insert({
      participantid: participantId,
      eventid: eventId,
      recommendationid: recom,
      surveysatisfactionscore: sat,
      surveyusefulnessscore: useful,
      surveyinstructorscore: instr,
      surveyrecommendationscore: recom,
      surveyoverallscore: overall,
      surveycomments: SurveyComments || null,
      surveysubmissiondate: knex.fn.now(),
    });

    // 4) Send confirmation email via Mailtrap
    try {
      await mailtrapClient.sendMail({
  from: mailSender,
  to: [{ address: SurveyEmail }],
  subject: "Thank you for completing the Ella Rises survey",
  text:
    "Thank you for taking the time to complete our post event survey for Ella Rises. Your feedback helps us improve future events and better support young women in STEAM.",
  html: `
  <!DOCTYPE html>
  <html>
    <head>
      <meta charset="UTF-8" />
      <title>Thank you from Ella Rises</title>
      <style>
        body, table, td, p { margin: 0; padding: 0; }
      </style>
    </head>
    <body style="background-color:#f5f5f5; font-family: Arial, sans-serif; color:#333333;">
      <table width="100%" border="0" cellspacing="0" cellpadding="0" style="padding: 20px 0;">
        <tr>
          <td align="center">
            <table width="600" border="0" cellspacing="0" cellpadding="0" style="background-color:#ffffff; border-radius:8px; overflow:hidden; box-shadow:0 2px 6px rgba(0,0,0,0.08);">
              <!-- Header -->
              <tr>
                <td align="center" style="background: linear-gradient(90deg, #99B7C6, #F9AFB1); padding: 24px 20px;">
                  <h1 style="margin:0; font-size:24px; color:#ffffff; font-weight:600;">
                    Ella Rises
                  </h1>
                  <p style="margin:8px 0 0; font-size:14px; color:#fdfdfd;">
                    Empowering young women in STEAM
                  </p>
                </td>
              </tr>

              <!-- Body -->
              <tr>
                <td style="padding: 24px 28px;">
                  <p style="font-size:16px; margin-bottom:16px;">
                    Hi,
                  </p>

                  <p style="font-size:15px; line-height:1.6; margin-bottom:16px;">
                    Thank you for taking the time to complete our post event survey for <strong>Ella Rises</strong>.
                    Your feedback plays a direct role in how we improve our programs and better support young women
                    as they explore opportunities in STEAM.
                  </p>

                  ${
                    SurveyEventDate
                      ? `
                      <p style="font-size:15px; margin-bottom:16px;">
                        <strong>Event date:</strong> ${SurveyEventDate}
                      </p>
                    `
                      : ""
                  }

                  <!-- Survey summary block -->
                  <h2 style="font-size:18px; margin:24px 0 12px;">Survey summary</h2>

                  <table width="100%" cellpadding="6" cellspacing="0" style="border-collapse:collapse; font-size:14px;">
                    <tr>
                      <td style="background-color:#f9f9f9; width:40%; font-weight:600;">Participant ID</td>
                      <td style="background-color:#f9f9f9;">${participantId}</td>
                    </tr>
                    <tr>
                      <td style="width:40%; font-weight:600;">Event ID</td>
                      <td>${eventId}</td>
                    </tr>
                    <tr>
                      <td style="background-color:#f9f9f9; font-weight:600;">Recommendation ID</td>
                      <td style="background-color:#f9f9f9;">${recom}</td>
                    </tr>
                    <tr>
                      <td style="font-weight:600;">Satisfaction score</td>
                      <td>${sat}</td>
                    </tr>
                    <tr>
                      <td style="background-color:#f9f9f9; font-weight:600;">Usefulness score</td>
                      <td style="background-color:#f9f9f9;">${useful}</td>
                    </tr>
                    <tr>
                      <td style="font-weight:600;">Instructor score</td>
                      <td>${instr}</td>
                    </tr>
                    <tr>
                      <td style="background-color:#f9f9f9; font-weight:600;">Recommendation score</td>
                      <td style="background-color:#f9f9f9;">${recom}</td>
                    </tr>
                    <tr>
                      <td style="font-weight:600;">Overall score</td>
                      <td>${overall}</td>
                    </tr>
                    <tr>
                      <td style="background-color:#f9f9f9; font-weight:600;">Comments</td>
                      <td style="background-color:#f9f9f9;">${SurveyComments ? SurveyComments : "None provided"}</td>
                    </tr>
                    <tr>
                      <td style="font-weight:600;">Submission date</td>
                      <td>${knex.fn.now().toLocaleString("en-US", { timeZone: "America/Denver" })}</td>
                    </tr>
                  </table>

                  <p style="font-size:15px; line-height:1.6; margin-top:24px; margin-bottom:0;">
                    We are grateful you chose to spend time with us and to share your perspective.
                  </p>

                  <p style="font-size:15px; line-height:1.6; margin-top:12px; margin-bottom:4px;">
                    With gratitude,
                  </p>
                  <p style="font-size:15px; line-height:1.4; margin-bottom:0;">
                    The Ella Rises Team
                  </p>
                </td>
              </tr>

              <!-- Footer -->
              <tr>
                <td align="center" style="background-color:#fafafa; padding: 16px 20px;">
                  <p style="font-size:12px; color:#777777; margin:0;">
                    Ella Rises | Supporting young women through mentoring, creativity, and leadership
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
  </html>
  `,
  category: "survey-confirmation",
});
      console.log("Survey confirmation email sent to:", SurveyEmail);
    } catch (emailErr) {
      console.error("Survey email send error:", emailErr);
      // do not throw - survey already saved
    }

    // 5) Redirect to thank you page
    res.redirect("/survey/thankyou");
  } catch (err) {
    console.error("Survey submit error:", err);

    const events = await knex("eventdefinition")
      .select("eventdefid", "eventname")
      .orderBy("eventdefid", "asc");

    res.status(500).render("survey/surveys", {
      events,
      error_message:
        "There was a problem saving your survey. Please try again.",
    });
  }
});


// app.post("/survey", async (req, res) => {
//   const {
//     SurveyEmail,
//     SurveyEventId,
//     SurveyEventDate,
//     SurveySatisfactionScore,
//     SurveyUsefulnessScore,
//     SurveyInstructorScore,
//     SurveyRecommendationScore,

//     SurveyComments
//   } = req.body;

//   try {
//     // 1) Look up participant by email using knex.raw
//     const emailResult = await knex.raw(
//       "SELECT participantid, participantemail FROM participant WHERE participantemail = ?",
//       [SurveyEmail]
//     );

//     // With Postgres, knex.raw returns { rows: [...] }
//     const rows = emailResult.rows || emailResult;

//     if (!rows || rows.length === 0) {
//       // Email not found, reload page with error
//       const events = await knex("eventdefinition")
//         .select("eventdefid", "eventname")
//         .orderBy("eventdefid", "asc");

//       return res.status(400).render("surveys", {
//         events,
//         error_message: "We could not find that email in our records. Please use the email you used to register."
//       });
//     }

//     const participantId = rows[0].participantid;

//     // Parse scores to integers
//     const sat = Number(SurveySatisfactionScore);
//     const useful = Number(SurveyUsefulnessScore);
//     const instr = Number(SurveyInstructorScore);
//     const recom = Number(SurveyRecommendationScore);

//     const overall = Math.round((sat + useful + instr + recom) / 4);

//     // 2) Insert into survey table
//      await knex("survey").insert({
//       participantid: participantId,
//       eventid: SurveyEventId,
//       recommendationid: recom,            // or whatever id you actually want here
//       surveysatisfactionscore: sat,
//       surveyusefulnessscore: useful,
//       surveyinstructorscore: instr,
//       surveyrecommendationscore: recom,
//       surveyoverallscore: overall,        // now an int, not 1388.75
//       surveycomments: SurveyComments || null,
//       surveysubmissiondate: knex.fn.now()
//     });

//     // 3) Redirect to a thank you page or something similar
//     res.redirect("/survey/thankyou");
//   } catch (err) {
//     console.error("Survey submit error:", err);

//     const events = await knex("eventdefinition")
//       .select("eventdefid", "eventname")
//       .orderBy("eventdefid", "asc");

//     res.status(500).render("surveys", {
//       events,
//       error_message: "There was a problem saving your survey. Please try again."
//     });
//   }
// });

app.get("/survey/thankyou", (req, res) => {
    res.render("survey/surveyThankYou");
}); 

app.get("/survey/responses", async (req, res) => {
  const { eventDefId, participantName } = req.query;
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

    // Filter by event definition if provided
    if (eventDefId && eventDefId !== "") {
      baseQuery = baseQuery.where("e.eventdefid", Number(eventDefId));
    }

    // Filter by participant full name (case insensitive)
    if (participantName && participantName.trim() !== "") {
      const nameTerm = `%${participantName.trim().toLowerCase()}%`;
      baseQuery = baseQuery.whereRaw(
        "LOWER(COALESCE(p.participantfirstname, '') || ' ' || COALESCE(p.participantlastname, '')) LIKE ?",
        [nameTerm]
      );
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
        knex.raw(`
          COALESCE(p.participantfirstname, '') ||
          CASE
            WHEN p.participantfirstname IS NOT NULL
             AND p.participantlastname IS NOT NULL
            THEN ' '
            ELSE ''
          END ||
          COALESCE(p.participantlastname, '') AS participantname
        `),
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

    res.render("survey/surveyResponses", {
      surveys,
      events,
      selectedEventDefId: eventDefId || "",
      participantName: participantName || "",
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

    res.render("survey/surveyEdit", {
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

// Helper to send a donation receipt
async function sendDonationReceipt({ toEmail, amount, isAnonymous, donationDate }) {
  if (!toEmail) return;

  const formattedDate = donationDate.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  const subject = "Your Ella Rises donation receipt";

  const text = `
Thank you for your generous donation to Ella Rises.

Amount: $${amount.toFixed(2)}
Date: ${formattedDate}
Donation type: ${isAnonymous ? "Anonymous" : "Named"}

This email serves as your receipt for tax purposes. 
No goods or services were provided in exchange for this contribution.

With gratitude,
Ella Rises
  `.trim();

  const html = `
  <div style="font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color:#333; line-height:1.5;">
    <div style="max-width:600px; margin:0 auto; padding:24px;">
      <h2 style="margin-top:0; color:#CE325B; font-weight:700;">
        Thank you for supporting Ella Rises
      </h2>

      <p>
        We are grateful for your recent ${isAnonymous ? "anonymous " : ""}donation to Ella Rises.
        Your gift helps young Latinas in Utah see themselves in college, in STEAM fields,
        and as leaders in their communities.
      </p>

      <div style="margin:20px 0; padding:16px 18px; border-radius:12px; background:#F9F5EA; border:1px solid #FFD8D1;">
        <h3 style="margin:0 0 10px 0; font-size:16px;">Donation Summary</h3>
        <p style="margin:4px 0;"><strong>Amount:</strong> $${amount.toFixed(2)}</p>
        <p style="margin:4px 0;"><strong>Date:</strong> ${formattedDate}</p>
        <p style="margin:4px 0;"><strong>Donation type:</strong> ${isAnonymous ? "Anonymous" : "Named"}</p>
      </div>

      <p style="font-size:14px; margin-top:18px;">
        This email serves as your donation receipt. No goods or services were provided
        in exchange for this contribution. Please keep this for your records.
      </p>

      <p style="margin-top:18px;">
        With gratitude,<br/>
        <strong>Ella Rises</strong>
      </p>

      <hr style="margin:24px 0; border:none; border-top:1px solid #eee;"/>

      <p style="font-size:12px; color:#666; margin:0;">
        If you have questions about this donation, reply to this email.
      </p>
    </div>
  </div>
  `;

  await mailtrapClient.sendMail({
    from: mailSender,
    to: [{ address: toEmail }],
    subject,
    text,
    html,
    category: "donation_receipt",
  });
}


app.post("/donations/add", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      email,
      phone,
      amount_choice,
      other_amount,
      anonymous,
      // frequency,
      // designation,
      // note,
      // updates,
    } = req.body;

    const ANONYMOUS_PARTICIPANT_ID = 1182;
    const isAnonymous =
      anonymous === "1" ||
      anonymous === "on" ||
      anonymous === true;

    const donationDate = new Date();

    // Validation:
    // - Email always required
    // - Name and phone required only if NOT anonymous
    if (!email || (!isAnonymous && (!first_name || !last_name || !phone))) {
      return res.status(400).render("donations", {
        error_message: "First name, last name, email, and phone are required unless you choose to donate anonymously.",
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

    if (!donationAmount || donationAmount <= 0) {
      return res.status(400).render("donations", {
        error_message: "Please choose or enter a valid donation amount.",
      });
    }

    let participantIdForDonation;

    if (isAnonymous) {
      // 2a. Anonymous donations get tied to the single anonymous participant row
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

      participantIdForDonation = ANONYMOUS_PARTICIPANT_ID;

      // Notice: no personal participant row is created or updated for this email.
      // You can still email them a receipt using `email` from req.body directly.
    } else {
      // 2b. Normal path, tie donation to real participant
      let participant = await knex("participant")
        .where({ participantemail: email })
        .first();

      if (!participant) {
        // New participant
        const [inserted] = await knex("participant")
          .insert({
            participantfirstname: cap(first_name),
            participantlastname: cap(last_name),
            participantemail: email,
            participantphone: phone,
            participantrole: "participant",
            totaldonations: donationAmount,
          })
          .returning(["participantid", "totaldonations"]);

        participant = inserted;
      } else {
        // Existing participant, bump totals and optionally refresh info
        const currentTotal = Number(participant.totaldonations) || 0;
        const newTotal = currentTotal + donationAmount;

        await knex("participant")
          .where({ participantid: participant.participantid })
          .update({
            totaldonations: newTotal,
            participantfirstname: cap(first_name),
            participantlastname: cap(last_name),
            participantphone: phone,
          });

        participant.totaldonations = newTotal;
      }

      participantIdForDonation = participant.participantid;
    }

    // 3. Calculate donationnumber based on the participant that this donation belongs to
    const countRow = await knex("donation")
      .where({ participantid: participantIdForDonation })
      .count("* as count")
      .first();

    const previousCount = Number(countRow.count) || 0;
    const donationNumber = previousCount + 1;

    // 4. Insert into donations
    await knex("donation").insert({
      participantid: participantIdForDonation,
      donationnumber: donationNumber,
      donationamount: donationAmount,
      donationdate: new Date(),
      isanonymous: isAnonymous,
    });

    // 5. Send receipt email here using `email` from req.body
    // await mailer.sendReceipt(email, donationAmount, ...);

    try {
      await sendDonationReceipt({
        toEmail: email,
        amount: donationAmount,
        isAnonymous,
        donationDate,
      });
    } catch (emailErr) {
      console.error("Failed to send receipt email:", emailErr);
      // do not block redirect if email fails
    }

    res.redirect("/donations/thank-you");
  } catch (err) {
    console.error("Donation error:", err);
    next(err);
  }
});


app.get("/donations/thank-you", (req, res) => { 
    res.render("donation/donationThankYou");
});



// GET /donations
app.get('/donations/view', async (req, res) => {
  try {
    const pageSize = 25;
    const rawPage = parseInt(req.query.page, 10) || 1;
    const page = Math.max(rawPage, 1);

    const {
      participantSearch,
      eventSearch,
      minAmount,
      maxAmount
    } = req.query;

    // Base query with Participant + PrimaryKey + Event + EventDefinition
    const baseQuery = knex('donation as d')
      .innerJoin('participant as p', 'd.participantid', 'p.participantid')
      .innerJoin('primarykey as pk', 'd.donationid', 'pk.donationid')
      .innerJoin('event as ev', 'pk.eventid', 'ev.eventid')
      .innerJoin('eventdefinition as ed', 'ev.eventdefid', 'ed.eventdefid');

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

    const countResult = await countQuery.countDistinct({ total: 'd.donationid' }).first();
    const totalCount = Number(countResult.total || 0);

    const totalPages = totalCount === 0 ? 1 : Math.ceil(totalCount / pageSize);
    const currentPage = Math.min(page, totalPages);
    const offset = (currentPage - 1) * pageSize;

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
        knex.raw(
          "coalesce(p.participantfirstname, '') || " +
          "case when p.participantfirstname is not null and p.participantlastname is not null then ' ' else '' end || " +
          "coalesce(p.participantlastname, '') as participantname"
        ),
        knex.raw("string_agg(distinct ed.eventname, ', ') as eventname"),
        'd.isanonymous'
      )
      .groupBy(
        'd.donationid',
        'd.donationnumber',
        'd.donationamount',
        'd.donationdate',
        'p.participantemail',
        knex.raw(
          "coalesce(p.participantfirstname, '') || " +
          "case when p.participantfirstname is not null and p.participantlastname is not null then ' ' else '' end || " +
          "coalesce(p.participantlastname, '')"
        ),
        'd.isanonymous'
      )
      .orderBy('d.donationdate', 'asc')
      .limit(pageSize)
      .offset(offset);

    const firstItem = totalCount === 0 ? 0 : offset + 1;
    const lastItem = offset + donations.length;

    // Sliding window of pages, size 10
    const windowSize = 10;
    const windowStart =
      Math.floor((currentPage - 1) / windowSize) * windowSize + 1;
    const windowEnd = Math.min(windowStart + windowSize - 1, totalPages);

    res.render('donation/viewDonations', {
      donations,
      participantSearch: participantSearch || '',
      eventSearch: eventSearch || '',
      minAmount: minAmount || '',
      maxAmount: maxAmount || '',
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
    console.error('Error loading donations:', err);
    res.status(500).send('Error loading donations');
  }
});

app.get("/donations/:id/edit", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!id) {
      return res.status(400).send("Invalid donation id");
    }

    const donation = await knex("donation as d")
      .leftJoin("participant as p", "d.participantid", "p.participantid")
      .leftJoin("primarykey as pk", "d.donationid", "pk.donationid")
      .leftJoin("event as ev", "pk.eventid", "ev.eventid")
      .leftJoin("eventdefinition as ed", "ev.eventdefid", "ed.eventdefid")
      .select(
        "d.donationid",
        "d.donationamount",
        "d.donationdate",
        "d.isanonymous",
        "d.participantid",
        knex.raw(
          "coalesce(p.participantfirstname, '') || " +
          "case when p.participantfirstname is not null and p.participantlastname is not null then ' ' else '' end || " +
          "coalesce(p.participantlastname, '') as participantname"
        ),
        "p.participantemail",
        "ed.eventname"
      )
      .where("d.donationid", id)
      .first();

    if (!donation) {
      return res.status(404).render("404");
    }

    // Format donationdate for datetime-local (YYYY-MM-DDTHH:MM)
    let donationdate_local = "";
    if (donation.donationdate) {
      const d = new Date(donation.donationdate);
      const pad = (n) => (n < 10 ? "0" + n : "" + n);
      const yyyy = d.getFullYear();
      const mm = pad(d.getMonth() + 1);
      const dd = pad(d.getDate());
      const hh = pad(d.getHours());
      const mi = pad(d.getMinutes());
      donationdate_local = `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
    }

    donation.donationdate_local = donationdate_local;

    res.render("donation/editDonation", {
      donation,
      error_message: ""
    });
  } catch (err) {
    console.error("Error loading donation for edit:", err);
    next(err);
  }
});


app.post("/donations/:id/edit", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!id) {
      return res.status(400).send("Invalid donation id");
    }

    const { donationamount, donationdate, isanonymous } = req.body;

    const newAmount = Number(donationamount);
    if (!newAmount || newAmount <= 0) {
      // reload original row to re-render form with error
      const donation = await knex("donation as d")
        .leftJoin("participant as p", "d.participantid", "p.participantid")
        .leftJoin("primarykey as pk", "d.donationid", "pk.donationid")
        .leftJoin("event as ev", "pk.eventid", "ev.eventid")
        .leftJoin("eventdefinition as ed", "ev.eventdefid", "ed.eventdefid")
        .select(
          "d.donationid",
          "d.donationamount",
          "d.donationdate",
          "d.isanonymous",
          "d.participantid",
          knex.raw(
            "coalesce(p.participantfirstname, '') || " +
            "case when p.participantfirstname is not null and p.participantlastname is not null then ' ' else '' end || " +
            "coalesce(p.participantlastname, '') as participantname"
          ),
          "p.participantemail",
          "ed.eventname"
        )
        .where("d.donationid", id)
        .first();

      if (donation) {
        let donationdate_local = "";
        if (donation.donationdate) {
          const d = new Date(donation.donationdate);
          const pad = (n) => (n < 10 ? "0" + n : "" + n);
          const yyyy = d.getFullYear();
          const mm = pad(d.getMonth() + 1);
          const dd = pad(d.getDate());
          const hh = pad(d.getHours());
          const mi = pad(d.getMinutes());
          donationdate_local = `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
        }
        donation.donationdate_local = donationdate_local;
      }

      return res.status(400).render("editDonation", {
        donation,
        error_message: "Please enter a valid donation amount."
      });
    }

    // Get existing donation so we can adjust participant totals
    const existing = await knex("donation")
      .where({ donationid: id })
      .first();

    if (!existing) {
      return res.status(404).render("404");
    }

    const oldAmount = Number(existing.donationamount) || 0;
    const delta = newAmount - oldAmount;

    // Normalize date
    let newDate = existing.donationdate;
    if (donationdate && donationdate.trim() !== "") {
      newDate = new Date(donationdate);
    }

    const newIsAnonymous = !!isanonymous;

    await knex.transaction(async (trx) => {
      // Update donation row
      await trx("donation")
        .where({ donationid: id })
        .update({
          donationamount: newAmount,
          donationdate: newDate,
          isanonymous: newIsAnonymous
        });

      // Update participant totaldonations if needed
      if (delta !== 0 && existing.participantid) {
        const participant = await trx("participant")
          .where({ participantid: existing.participantid })
          .first();

        if (participant) {
          const currentTotal = Number(participant.totaldonations) || 0;
          await trx("participant")
            .where({ participantid: existing.participantid })
            .update({
              totaldonations: currentTotal + delta
            });
        }
      }
    });

    res.redirect("/donations/view");
  } catch (err) {
    console.error("Error updating donation:", err);
    next(err);
  }
});

app.post("/donations/:id/delete", async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!id) {
      return res.status(400).send("Invalid donation id");
    }

    // Get the existing donation so we know amount and participant
    const existing = await knex("donation")
      .where({ donationid: id })
      .first();

    if (!existing) {
      // Nothing to delete - just go back to the list
      return res.redirect("/donations/view");
    }

    const donationAmount = Number(existing.donationamount) || 0;
    const participantId = existing.participantid;

    await knex.transaction(async (trx) => {
      // Adjust participant.totaldonations if this donation was tied to a participant
      if (participantId) {
        const participant = await trx("participant")
          .where({ participantid: participantId })
          .first();

        if (participant) {
          const currentTotal = Number(participant.totaldonations) || 0;
          let newTotal = currentTotal - donationAmount;
          if (newTotal < 0) newTotal = 0;

          await trx("participant")
            .where({ participantid: participantId })
            .update({ totaldonations: newTotal });
        }
      }

      // Clean up primarykey row if one exists
      await trx("primarykey")
        .where({ donationid: id })
        .del();

      // Finally delete the donation itself
      await trx("donation")
        .where({ donationid: id })
        .del();
    });

    res.redirect("/donations/view");
  } catch (err) {
    console.error("Error deleting donation:", err);
    next(err);
  }
});

app.get('/donations/new', async (req, res) => {
  try {
    const participants = await knex('participant')
      .select(
        'participantid',
        'participantfirstname',
        'participantlastname',
        'participantemail'
      )
      .orderBy('participantlastname')
      .orderBy('participantfirstname');

    const events = await knex("eventdefinition")
      .select("eventdefid", "eventname")
      .orderBy("eventdefid", "asc");

    res.render('donation/adminDonation', {
      participants,
      events,
      error_message: null
    });
  } catch (err) {
    console.error('Error loading add donation view:', err);
    res.render('donation/adminDonation', {
      participants: [],
      events: [],
      error_message: 'Error loading data for new donation.'
    });
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
        const result = await knex.raw(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (!result.rows || result.rows.length === 0) {
            return res.status(401).render('login', {
                error_message: 'Invalid username or password.',
                username // optional: prefill the username field
            });
        }

        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).render('login', {
                error_message: 'Invalid username or password.',
                username
            });
        }

        // Success
        req.session.user = {
            // if your table uses participantid, fix this:
            id: user.participantid || user.id,
            username: user.username,
            role: user.role
        };
        req.session.isLoggedIn = true;

        const redirectTo = req.session.redirectTo || '/';
        delete req.session.redirectTo;

        return res.redirect(redirectTo);

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).render('login', {
            error_message: 'An error occurred during login. Please try again.',
            username
        });
    }
});


// Logout route
app.get("/logout", (req, res) => {
    // Get rid of the session object
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
        }
        res.redirect("/");
    });
});

// Donation Routes
app.get("/donations", (req, res) => {
    res.render("donation/donations");
});

app.get('/profile', async (req, res) => {
    
    // 1. Check if the user object exists in the session (Guard Clause)
    const currentUser = req.session.user;

    if (!currentUser || !currentUser.id) {

        return res.redirect('/login'); 
    }
    
    const userId = currentUser.id;

    // --- QUERY 1: Fetch Profile Data (User + Participant Info) ---
    const profileQuery = `
        SELECT 
            u.username, 
            u.role, 
            u.id, 
            p.*
        FROM 
            users u
        JOIN 
            participant p ON p.participantid = u.id
        WHERE 
            u.id = ?; 
    `;

    // --- QUERY 2: Fetch Donation History ---
    const donationHistoryQuery = `
        SELECT 
            donationnumber,
            donationdate, 
            donationamount
            FROM 
            donation 
        WHERE 
            participantid = ?
        ORDER BY 
            donationdate DESC; -- Ordering by date descending (newest first)
    `;

    // --- QUERY 3: Fetch Milestones History ---
    const milestoneQuery = `
        SELECT 
            milestonetitle, 
            milestonedate
        FROM 
            milestone 
        WHERE 
            participantid = ?
        ORDER BY 
            milestonedate DESC; -- Ordering by date descending (newest first)
    `;

    try {
        // EXECUTE QUERY 1: Get Profile Data
        const profileResult = await knex.raw(profileQuery, [userId]); 
        const profileData = profileResult.rows[0]; 


        if (!profileData) {
            return res.status(404).send('Profile data not found. Check if user is in participant table.');
        }

        // EXECUTE QUERY 2: Get Donation History
        const donationResult = await knex.raw(donationHistoryQuery, [userId]); 
        const donationHistory = donationResult.rows; 

        // EXECUTE QUERY 3: Get Milestones History
        const milestoneResult = await knex.raw(milestoneQuery, [userId]); 
        const milestonesHistory = milestoneResult.rows; 

        // 4. Render the page, passing ALL three sets of data
        res.render('profile', {
            users: { 
                ...profileData,
            },
            donations: donationHistory,
            milestones: milestonesHistory // <-- NEW DATA SET
        });

    } catch (error) {
        console.error('Error fetching data:', error);
        // The previous console output was very helpful! Keep an eye on the terminal 
        // for specific errors if this fails.
        res.status(500).send('Server Error retrieving data.');
    }
});

// -----------------------------------------------------
// MILESTONE ROUTES - Access restricted to 'manager' role
// -----------------------------------------------------

// Milestones list + search
app.get('/milestones', async (req, res) => {
  const pageSize = 100;

  let { page, search_name, search_milestone, date } = req.query;

  let currentPage = parseInt(page, 10);
  if (isNaN(currentPage) || currentPage < 1) {
    currentPage = 1;
  }

  search_name = search_name ? search_name.trim() : "";
  search_milestone = search_milestone ? search_milestone.trim() : "";
  date = date ? date.trim() : "";

  // base query
  const baseQuery = knex("milestone as m")
    .innerJoin("participant as p", "m.participantid", "p.participantid");

  const applyFilters = (query) => {
    if (search_name) {
      query.whereRaw(
        "LOWER(p.participantfirstname || ' ' || p.participantlastname) LIKE ?",
        [`%${search_name.toLowerCase()}%`]
      );
    }

    if (search_milestone) {
      query.whereRaw(
        "LOWER(m.milestonetitle) LIKE ?",
        [`%${search_milestone.toLowerCase()}%`]
      );
    }

    if (date) {
      query.where("m.milestonedate", "<=", date);
    }

    return query;
  };

  try {
    // count
    const countRow = await applyFilters(baseQuery.clone())
      .countDistinct({ total: "m.milestoneid" })
      .first();

    const totalRows = parseInt(countRow?.total || 0, 10);
    const totalPages = totalRows > 0 ? Math.ceil(totalRows / pageSize) : 1;

    const safePage = Math.min(currentPage, totalPages);
    const offset = (safePage - 1) * pageSize;

    // data
    const milestone = await applyFilters(baseQuery.clone())
      .select(
        "m.milestoneid",
        "m.milestonetitle",
        "m.milestonedate",
        "p.participantfirstname",
        "p.participantlastname",
        "p.participantemail",
        "p.participantid"
      )
      .orderBy("p.participantid", "asc")
      .orderBy("m.milestoneid", "asc")
      .limit(pageSize)
      .offset(offset);

    // sliding window pagination
    const windowSize = 10;
    const windowStart =
      Math.floor((safePage - 1) / windowSize) * windowSize + 1;
    const windowEnd = Math.min(windowStart + windowSize - 1, totalPages);

    res.render("milestone/milestones", {
      milestone,
      search_name,
      search_milestone,
      date,
      error_message: "",
      pagination: {
        currentPage: safePage,
        totalPages,
        totalRows,
        pageSize,
        windowSize,
        windowStart,
        windowEnd
      }
    });
  } catch (err) {
    console.error("Error loading milestones:", err);

    res.render("milestone/milestones", {
      milestone: [],
      search_name,
      search_milestone,
      date,
      error_message: "There was a problem loading milestones.",
      pagination: {
        currentPage: 1,
        totalPages: 1,
        totalRows: 0,
        pageSize,
        windowSize: 10,
        windowStart: 1,
        windowEnd: 1
      }
    });
  }
});

// edit milestone get route - Access restricted to 'manager' role
app.get("/editMilestone/:id", requireManager, (req, res) => {
    const milestoneId = req.params.id;
    knex("milestone")
        .where({ milestoneid: milestoneId })
        .first()
        .then((milestone) => {
            if (!milestone) {
                return res.status(404).render("milestone/milestones", {
                    milestone: [],
                    error_message: "Milestone not found."
                });
            }
            res.render("milestone/editmilestone", { milestone, error_message: "" });
        })
        .catch((err) => {
            console.error("Error fetching milestone:", err.message);
            res.status(500).render("milestone/milestones", {
                workshops: [],
                error_message: "Unable to load milestone for editing."
            });
        });
});

// Edit Milestone POST Route - Access restricted to 'manager' role
app.post("/editMilestone/:id", requireManager, (req, res) => {
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
});

// delete milestone - Access restricted to 'manager' role
app.post("/deleteMilestone/:id", requireManager, (req, res) => {
    knex("milestone").where("milestoneid", req.params.id).del().then(milestone => {
        res.redirect("/milestones");
    }).catch(err => {
        console.error(err);
        res.status(500).json({err});
    })
});

app.get("/addMilestone", requireManager, (req, res) => {
    res.render("milestone/addmilestone",
            { error_message: "" }
        );
});

app.post("/addmilestone", requireManager, (req, res) => {
    const { milestonetitle, milestonedate } = req.body;
    let { participantIdentifier } = req.body;
    participantIdentifier = participantIdentifier.trim();
    // validation check
    if (!milestonetitle || !milestonedate || !participantIdentifier) {
        // FIX: Pass error_message string directly for validation error
        return res.status(400).render("milestone/addmilestone", {
            error_message: "Milestone Title, Date, and Participant Identifier are required."
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
            // FIX: Pass error_message string directly for database/lookup errors
            res.status(500).render("milestone/addmilestone", {
                 error_message: errorMessage
            });
        });
});

// -----------------------------------------------------
// HELPER FUNCTION: Fetch paginated participants
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
        console.error("Database query error in fetchAllParticipants:", error.message);
        // Re-throw the error so the main route can catch it
        throw new Error("Failed to fetch participants from database.");
    }
};

// -----------------------------------------------------
// PARTICIPANT ROUTES - Access restricted to 'manager' role
// -----------------------------------------------------

// GET /participants - Display the list of all participants with pagination and search
app.get('/participants', requireViewerOrManager, async (req, res) => {
  // Setup user object for EJS rendering
  const user = req.session.user
    ? {
        ...req.session.user,
        name: req.session.user.username,
        isManager: req.session.user.role === 'manager'
      }
    : { username: 'Guest', role: 'guest' };

  // Get and clear session message
  const message = req.session.message;
  delete req.session.message;

  const limit = 100;
  const rawPage = parseInt(req.query.page, 10) || 1;
  const page = Math.max(rawPage, 1);

  // Search Parameters
  const { search_name, search_id, search_email, search_phone } = req.query;

  // Apply filters helper
  const applyFilters = (queryBuilder) => {
    queryBuilder.where(function () {
      const builder = this;
      let firstCondition = true;

      const chainCondition = (conditionFunc) => {
        if (firstCondition) {
          builder.where(conditionFunc);
          firstCondition = false;
        } else {
          builder.andWhere(conditionFunc);
        }
      };

      // 1. Name
      if (search_name) {
        const wildCardSearch = `%${search_name.toLowerCase()}%`;

        chainCondition(function () {
          this.whereRaw('LOWER(participantfirstname) LIKE ?', [wildCardSearch])
            .orWhereRaw('LOWER(participantlastname) LIKE ?', [wildCardSearch]);
        });
      }

      // 2. ID
      if (search_id) {
        chainCondition(function () {
          if (!isNaN(parseInt(search_id))) {
            this.where('participantid', parseInt(search_id));
          } else {
            const wildCardSearch = `%${search_id}%`;
            this.where('participantid', 'LIKE', wildCardSearch);
          }
        });
      }

      // 3. Email
      if (search_email) {
        const wildCardSearch = `%${search_email.toLowerCase()}%`;

        chainCondition(function () {
          this.whereRaw('LOWER(participantemail) LIKE ?', [wildCardSearch]);
        });
      }

      // 4. Phone
      if (search_phone) {
        const wildCardSearch = `%${search_phone}%`;

        chainCondition(function () {
          this.where('participantphone', 'LIKE', wildCardSearch);
        });
      }
    });

    return queryBuilder;
  };

  try {
    // Count
    let countQuery = knex('participant').clone();
    countQuery = applyFilters(countQuery);
    const countResult = await countQuery.count('* as count').first();
    const totalCount = parseInt(countResult.count, 10) || 0;

    const totalPages = totalCount === 0 ? 1 : Math.ceil(totalCount / limit);
    const currentPage = Math.min(page, totalPages);
    const offset = (currentPage - 1) * limit;

    // Data
    let dataQuery = knex.select('*').from('participant');
    dataQuery = applyFilters(dataQuery);

    const participants = await dataQuery
      .orderBy('participantlastname', 'asc')
      .orderBy('participantfirstname', 'asc')
      .limit(limit)
      .offset(offset);

    console.log(
      `PARTICIPANT DATA STATUS: Fetched ${participants.length} participants for page ${currentPage} (Total: ${totalCount}).`
    );

    // Sliding window (like surveys and donations)
    const windowSize = 10;
    const windowStart =
      Math.floor((currentPage - 1) / windowSize) * windowSize + 1;
    const windowEnd = Math.min(windowStart + windowSize - 1, totalPages);

    res.render('participant/participants', {
      user,
      participants,
      message,
      error_message: null,
      pagination: {
        currentPage,
        totalPages,
        totalCount,
        limit,
        windowSize,
        windowStart,
        windowEnd
      },
      search_name,
      search_id,
      search_email,
      search_phone
    });
  } catch (error) {
    console.error('Participant Route Render Error:', error.message);

    res.render('participant/participants', {
      user,
      participants: [],
      message: null,
      error_message: error.message,
      pagination: {
        currentPage: 1,
        totalPages: 1,
        totalCount: 0,
        limit,
        windowSize: 10,
        windowStart: 1,
        windowEnd: 1
      },
      search_name: req.query.search_name,
      search_id: req.query.search_id,
      search_email: req.query.search_email,
      search_phone: req.query.search_phone
    });
  }
});


// GET /addParticipant - Display the form (Create Form) - Access restricted to 'manager' role
app.get("/addParticipant", requireManager, (req, res) => {
    
    const user = req.session.user ? {
        ...req.session.user,
        name: req.session.user.username,
        isManager: req.session.user.role === 'manager'
    } : { username: 'Guest', role: 'guest' };
    
    // Pass error_message as an empty string to prevent EJS crash
    res.render("participant/addparticipant", { message: null, user: user, error_message: "" });
});

// POST /addParticipant - Handle form submission (Create Action) - Access restricted to 'manager' role
app.post("/addParticipant", requireManager, async (req, res) => {
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

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).render("participant/addparticipant", {
            user: user,
            message: null,
            error_message: "Please enter a valid email address."
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

// GET /editParticipant/:id - Display the Participant Profile/Edit Form - Access restricted to 'manager' role
app.get('/editParticipant/:id', requireManager, async (req, res) => {
    const participantId = req.params.id;
    try {
        // 1. Fetch Participant Details (Ensure all columns are selected)
        const participant = await knex('participant')
            .select(
                'participantid',
                'participantfirstname',
                'participantlastname',
                'participantemail',
                'participantphone',   
                'participantcity',    
                'participantstate',   
                'participantzip',
                 'participantdob',
                  'participantschooloremployer',
                  'participantfieldofinterest' ,
                  'totaldonations' 
                // ... any other columns you need ...
            )
            .where({ participantid: participantId })
            .first();

        // Check if participant was found
        if (!participant) {
            req.session.error_message = 'Participant not found.';
            return res.redirect('/participants');
        }

        // Fetch Milestones
        const milestones = await knex('milestone')
            .select('milestonetitle', knex.raw('TO_CHAR(milestonedate, \'YYYY-MM-DD\') as milestonedate, milestoneid'))
            .where({ participantid: participantId })
            .orderBy('milestonedate', 'desc');

        // Render the page
        res.render('participant/editparticipant', { 
            participant: participant, 
            milestones: milestones,
            error_message: req.session.error_message 
        });
        req.session.error_message = null; // Clear session message

    } catch (err) {
        console.error(err);
        req.session.error_message = 'Database error when loading participant details.';
        res.redirect('/participants');
    }
});

// POST /editParticipant/:id - Handle form submission for editing (Update Action) - Access restricted to 'manager' role
app.post('/editParticipant/:id', requireManager, async (req, res) => {
    const participantId = req.params.id;
    // Destructure all fields from the form submission
    const { 
        firstName, 
        lastName, 
        email, 
        phone,    
        city,     
        state,    
        zip       
    } = req.body;

    // Basic validation (ensure required fields are present)
    if (!firstName || !lastName || !email) {
        req.session.error_message = 'First Name, Last Name, and Email are required.';
        return res.redirect(`/editParticipant/${participantId}`);
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        req.session.error_message = 'Please enter a valid email address.';
        return res.redirect(`/editParticipant/${participantId}`);
    }

    // Phone validation (if provided)
    if (phone && phone.trim() !== '') {
        const phoneRegex = /^[\(]?[0-9]{3}[\)]?[\s\-]?[0-9]{3}[\s\-]?[0-9]{4}$/;
        if (!phoneRegex.test(phone)) {
            req.session.error_message = 'Please enter a valid phone number (e.g., 555-555-5555 or (555) 555-5555).';
            return res.redirect(`/editParticipant/${participantId}`);
        }
    }

    // Zip code validation (if provided)
    if (zip && zip.trim() !== '') {
        const zipRegex = /^[0-9]{5}(-[0-9]{4})?$/;
        if (!zipRegex.test(zip)) {
            req.session.error_message = 'Please enter a valid 5-digit zip code or 9-digit zip+4 (e.g., 12345 or 12345-6789).';
            return res.redirect(`/editParticipant/${participantId}`);
        }
    }

    // State validation (if provided)
    if (state && state.trim() !== '') {
        const stateRegex = /^[A-Za-z]{2}$/;
        if (!stateRegex.test(state)) {
            req.session.error_message = 'Please enter a valid 2-letter state code (e.g., TX, CA, NY).';
            return res.redirect(`/editParticipant/${participantId}`);
        }
    }

    try {
        await knex('participant')
            .where({ participantid: participantId })
            .update({
                participantfirstname: firstName,
                participantlastname: lastName,
                participantemail: email,
                participantphone: phone || null, // Allow null if phone is empty
                participantcity: city || null,     // Allow null if city is empty
                participantstate: state || null,   // Allow null if state is empty
                participantzip: zip || null        // Allow null if zip is empty
            });

        // Use a success message (optional)
        req.session.message = { 
            type: 'success', 
            text: 'Participant details updated successfully!' 
        };
        res.redirect('/participants');

    } catch (err) {
        console.error(err);
        req.session.error_message = 'Failed to update participant details due to a database error.';
        res.redirect(`/editParticipant/${participantId}`);
    }
});

// POST /deleteParticipant/:id - Delete a participant (Delete Action) - Access restricted to 'manager' role
app.post("/deleteParticipant/:id", requireManager, (req, res) => {
    
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
        console.error(err);
        res.status(500).json({err});
    })
});

// -----------------------------------------------------
//  EVENT SYSTEM ROUTES (PUBLIC + MANAGER)
// -----------------------------------------------------

/* ================================================
   1. PUBLIC ROUTES (NO LOGIN REQUIRED)
   ================================================ */

// Public — Event List
app.get("/eventspublic", async (req, res) => {
    try {
        const eventDefs = await knex("eventdefinition")
            .select("eventdefid", "eventname", "eventdescription", "eventimage")
            .orderBy("eventname");

        res.render("events/eventspublic", { eventDefs });
    } catch (err) {
        console.error("Error loading public event list:", err);
        res.render("events/eventspublic", { eventDefs: [] });
    }
});

// -----------------------------------------------------
// PUBLIC: Event Detail Page (Shows all upcoming times)
// -----------------------------------------------------
app.get("/eventspublic/detail/:eventdefid", async (req, res) => {
    try {
        const eventdefid = req.params.eventdefid;

        // Fetch event definition info (name, description, image)
        const eventDef = await knex("eventdefinition")
            .select("eventdefid", "eventname", "eventdescription", "eventimage", "eventtype")
            .where("eventdefid", eventdefid)
            .first();

        if (!eventDef) {
            return res.status(404).render("404");
        }

        // Fetch all upcoming events of this event type
        const upcomingEvents = await knex("event")
            .select("eventid", "eventdatetimestart", "eventdatetimeend", "eventlocation")
            .where("eventdefid", eventdefid)
            .orderBy("eventdatetimestart", "asc");

        // Format date/time for dropdown
        const formattedEvents = upcomingEvents.map(ev => ({
            ...ev,
            label: new Date(ev.eventdatetimestart).toLocaleString("en-US", {
                year: "numeric",
                weekday: "short",
                month: "short",
                day: "numeric",
                hour: "numeric",
                minute: "2-digit"
            })
        }));

        res.render("events/eventpublicdetail", {
            eventDef,
            upcomingEvents: formattedEvents
        });

    } catch (err) {
        console.error("Error loading public event detail:", err);
        res.status(500).render("404");
    }
});

// Public — Event Detail Page
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

        res.render("events/eventdetail", { event });
    } catch (err) {
        console.error("Error loading event detail:", err);
        res.status(500).render("404");
    }
});

// Public — RSVP Page
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

        res.render("events/eventrsvp", { event });
    } catch (err) {
        console.error("Error loading RSVP page:", err);
        res.status(500).render("404");
    }
});

// Public — Submit RSVP
app.post("/events/rsvp/:id", async (req, res) => {
    try {
        // TODO: add DB insert later
        res.render("rsvpsuccess");
    } catch (err) {
        console.error("Error submitting RSVP:", err);
        res.status(500).render("404");
    }
});

/* ================================================
   2. MANAGER-ONLY ROUTES
   ================================================ */

// Middleware: Only allow managers (role 'manager' or 'm')
function requireManager(req, res, next) {
    // 1. Check if user is logged in
    if (!req.session.isLoggedIn || !req.session.user) {
        // Redirect to login, storing the original path
        req.session.redirectTo = req.originalUrl;
        return res.render("login", { error_message: "Please log in to access this page" });
    }

    // 2. Check for required role
    const role = req.session.user.role.toLowerCase().trim();

    if (role === "manager" || role === "m") {
        return next();
    }

    // 3. User is logged in but does not have the manager role
    return res.status(403).render("403");
}

// Middleware: Allow both viewers and managers (read-only pages)
function requireViewerOrManager(req, res, next) {
    // 1. Check if user is logged in
    if (!req.session.isLoggedIn || !req.session.user) {
        // Redirect to login, storing the original path
        req.session.redirectTo = req.originalUrl;
        return res.render("login", { error_message: "Please log in to access this page" });
    }

    // 2. Check for required role
    const role = req.session.user.role.toLowerCase().trim();

    if (role === "viewer" || role === "manager" || role === "m") {
        return next();
    }

    // 3. User is logged in but does not have viewer or manager role
    return res.status(403).render("403");
}

// -----------------------------------------------------
// MANAGER — Search All Events (Joined)
// -----------------------------------------------------
app.get("/events/manage/all", requireManager, async (req, res) => {
  const {
    search_name,
    search_location,
    search_type,
    search_start,
    search_end
  } = req.query;

  const pageSize = 100;
  const rawPage = parseInt(req.query.page, 10) || 1;
  const page = Math.max(rawPage, 1);

  try {
    // Base query
    const baseQuery = knex("event as e")
      .join("eventdefinition as d", "e.eventdefid", "d.eventdefid");

    // Filters
    const applyFilters = (q) => {
      if (search_name && search_name.trim() !== "") {
        q.whereILike("d.eventname", `%${search_name.trim()}%`);
      }

      if (search_location && search_location.trim() !== "") {
        q.whereILike("e.eventlocation", `%${search_location.trim()}%`);
      }

      if (search_type && search_type.trim() !== "") {
        q.where("d.eventtype", search_type);
      }

      if (search_start && search_start !== "") {
        q.where("e.eventdatetimestart", ">=", search_start);
      }

      if (search_end && search_end !== "") {
        q.where("e.eventdatetimestart", "<=", search_end);
      }

      return q;
    };

    // Count
    const countRow = await applyFilters(baseQuery.clone())
      .countDistinct({ total: "e.eventid" })
      .first();

    const totalRows = parseInt(countRow?.total || 0, 10);
    const totalPages = totalRows > 0 ? Math.ceil(totalRows / pageSize) : 1;

    const currentPage = Math.min(page, totalPages);
    const offset = (currentPage - 1) * pageSize;

    // Data query
    const rawEvents = await applyFilters(baseQuery.clone())
      .select(
        "e.eventid",
        "e.eventdatetimestart",
        "e.eventdatetimeend",
        "e.eventlocation",
        "d.eventname",
        "d.eventtype"
      )
      .orderBy("e.eventdatetimestart", "asc")
      .limit(pageSize)
      .offset(offset);

    // Format dates for display
    const events = rawEvents.map((ev) => {
      const start = new Date(ev.eventdatetimestart);
      const end = new Date(ev.eventdatetimeend);

      return {
        ...ev,
        startFormatted: start.toLocaleString("en-US", {
          month: "long",
          day: "numeric",
          year: "numeric",
          hour: "numeric",
          minute: "2-digit"
        }),
        endFormatted: end.toLocaleString("en-US", {
          month: "long",
          day: "numeric",
          year: "numeric",
          hour: "numeric",
          minute: "2-digit"
        })
      };
    });

    // Sliding window pagination
    const windowSize = 10;
    const windowStart =
      Math.floor((currentPage - 1) / windowSize) * windowSize + 1;
    const windowEnd = Math.min(windowStart + windowSize - 1, totalPages);

    res.render("events/manageallevents", {
      events,
      search_name,
      search_location,
      search_type,
      search_start,
      search_end,
      pagination: {
        currentPage,
        totalPages,
        totalRows,
        pageSize,
        windowSize,
        windowStart,
        windowEnd
      }
    });
  } catch (err) {
    console.error("Error loading all-event manager search:", err);
    res.status(500).render("events/manageallevents", {
      events: [],
      search_name,
      search_location,
      search_type,
      search_start,
      search_end,
      pagination: {
        currentPage: 1,
        totalPages: 1,
        totalRows: 0,
        pageSize,
        windowSize: 10,
        windowStart: 1,
        windowEnd: 1
      },
      error_message: "There was a problem loading events."
    });
  }
});

// Add Event via Calendar Modal — MUST COME FIRST
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

// Manual Add Event Form
app.get("/events/add", requireManager, (req, res) => {
    res.render("events/addevent", { error_message: "" });
});

// Submit Add Event
// ADD EVENT (with image upload)
app.post("/events/add", requireManager, upload.single("eventimage"), async (req, res) => {
    try {

        // --- GET THE UPLOADED IMAGE FILENAME (THIS IS WHAT YOU NEEDED) ---
        const imageFilename = req.file ? req.file.filename : null;

        // Insert into eventdefinition (includes image)
        const [def] = await knex("eventdefinition")
            .insert({
                eventname: req.body.eventname,
                eventdescription: req.body.eventdescription,
                eventtype: req.body.eventtype,
                eventrecurrencepattern: req.body.eventrecurrencepattern,
                eventimage: imageFilename   // <-- IMPORTANT
            })
            .returning("eventdefid");

        // Insert into event table
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

// Manager — Event List
app.get("/events", requireViewerOrManager, async (req, res) => {
    try {
        const eventDefs = await knex("eventdefinition")
        .select(
            "eventdefid",
            "eventname",
            "eventdescription",
            "eventimage"
        )
        .orderBy("eventname");


        res.render("events/eventlist", { eventDefs });
    } catch (err) {
        console.error("Error loading event definitions:", err);
        res.render("events/eventlist", { eventDefs: [] });
    }
});

// Manager — Event Details for a Day
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

// Manager — Event Calendar
app.get("/events/:eventdefid", requireManager, async (req, res) => {
    try {
        const eventDef = await knex("eventdefinition")
            .where("eventdefid", req.params.eventdefid)
            .first();

        const events = await knex("event")
            .where("eventdefid", req.params.eventdefid)
            .select("eventid", "eventdatetimestart");

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

// Manager — Edit Event
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

// Manager — Submit Event Edit
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

// Dashboard route with statistics
app.get("/dashboard", requireManager, async (req, res) => {
    try {
        const selectedYear = req.query.year || new Date().getFullYear();

        // 1. Total Participants Count
        const participantCount = await knex("participant").count("* as count").first();

        // 2. Total Donations (all time)
        const totalDonationsResult = await knex("donation")
            .sum("donationamount as total")
            .first();
        const totalDonations = totalDonationsResult.total || 0;

        // 3. Average Donation per Participant
        const avgDonation = participantCount.count > 0
            ? (totalDonations / participantCount.count).toFixed(2)
            : 0;

        // 4. Total Events Held
        const eventCount = await knex("event").count("* as count").first();

        // 5. Milestone Completion Percentage
        const totalMilestones = await knex("milestone").count("* as count").first();
        const completedMilestones = await knex("milestone")
            .where("milestonedate", "<", knex.fn.now())
            .count("* as count")
            .first();
        const completionPercentage = totalMilestones.count > 0
            ? ((completedMilestones.count / totalMilestones.count) * 100).toFixed(1)
            : 0;

        // 6. Donations by Month for Selected Year
        const donationsByMonth = await knex("donation")
            .select(knex.raw("EXTRACT(MONTH FROM donationdate) as month"))
            .sum("donationamount as total")
            .whereRaw("EXTRACT(YEAR FROM donationdate) = ?", [selectedYear])
            .groupBy(knex.raw("EXTRACT(MONTH FROM donationdate)"))
            .orderBy("month");

        // Format donations data for chart (fill in missing months with 0)
        const monthlyData = Array.from({ length: 12 }, (_, i) => {
            const monthData = donationsByMonth.find(d => parseInt(d.month) === i + 1);
            return monthData ? parseFloat(monthData.total) : 0;
        });

        // 8. Get available years for dropdown
        const availableYearsResult = await knex("donation")
            .select(knex.raw("DISTINCT EXTRACT(YEAR FROM donationdate) as year"))
            .orderBy("year", "desc");
        const availableYears = availableYearsResult.map(r => parseInt(r.year));

        // 7. Upcoming Birthdays (this week)
        const birthdaysResult = await knex.raw(`
            SELECT participantfirstname, participantlastname, participantdob
            FROM participant
            WHERE participantdob IS NOT NULL
              AND (
                (EXTRACT(MONTH FROM participantdob), EXTRACT(DAY FROM participantdob)) IN (
                  SELECT EXTRACT(MONTH FROM date)::int, EXTRACT(DAY FROM date)::int
                  FROM generate_series(CURRENT_DATE, CURRENT_DATE + INTERVAL '6 days', INTERVAL '1 day') AS date
                )
              )
            ORDER BY EXTRACT(MONTH FROM participantdob), EXTRACT(DAY FROM participantdob)
            LIMIT 50
        `);
        const upcomingBirthdays = birthdaysResult.rows;

        res.render("tableau", {
            stats: {
                totalParticipants: participantCount.count,
                totalDonations: parseFloat(totalDonations).toFixed(2),
                avgDonation: avgDonation,
                totalEvents: eventCount.count,
                completionPercentage: completionPercentage,
                completedMilestones: completedMilestones.count,
                totalMilestones: totalMilestones.count
            },
            monthlyData: monthlyData,
            selectedYear: parseInt(selectedYear),
            availableYears: availableYears,
            upcomingBirthdays: upcomingBirthdays
        });
    } catch (error) {
        console.error("Error fetching dashboard data:", error);
        res.status(500).render("tableau", {
            stats: {},
            monthlyData: [],
            selectedYear: new Date().getFullYear(),
            availableYears: [],
            upcomingBirthdays: [],
            error_message: "Error loading dashboard data"
        });
    }
});

// Legacy tableau route (redirect to dashboard)
app.get("/tableau", requireManager, async (req, res) => {
    res.redirect("/dashboard");
});

// -----------------------------------------------------
// DELETE ENTIRE EVENT DEFINITION + ALL CHILD EVENTS
// -----------------------------------------------------
app.post("/events/fulldelete/:id", requireManager, async (req, res) => {
    try {
        const id = req.params.id;

        // delete event rows first due to FK
        await knex("event").where("eventdefid", id).del();

        // delete eventdefinition
        await knex("eventdefinition").where("eventdefid", id).del();

        res.redirect("/events/manage");
    } catch (err) {
        console.error("Error deleting full event:", err);
        res.redirect("/events/manage");
    }
});

// Manager — Delete Event
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

// Users list + search (Pagination and Filtering)
app.get("/users", async (req, res) => {
  const pageSize = 100;
  let { page, search_name } = req.query;

  let currentPage = parseInt(page, 10);
  if (isNaN(currentPage) || currentPage < 1) {
    currentPage = 1;
  }

  search_name = search_name ? search_name.trim() : "";
  const isSearching = !!search_name;

  try {
    // Base query for the 'users' table
    const baseQuery = knex("users");

    // Reusable filter function – search by username
    const applyFilters = (query) => {
      if (search_name) {
        const searchTerm = `%${search_name.toLowerCase()}%`;

        query.where(function () {
          this.whereRaw("LOWER(username) LIKE ?", [searchTerm]);
        });
      }
      return query;
    };

    // Count distinct participantid for pagination
    const countRow = await applyFilters(baseQuery.clone())
      .countDistinct({ total: "participantid" })
      .first();

    const totalRows = parseInt(countRow?.total || 0, 10);
    const totalPages = totalRows > 0 ? Math.ceil(totalRows / pageSize) : 1;

    const safePage = Math.min(currentPage, totalPages);
    const offset = (safePage - 1) * pageSize;

    // Data query
    const users = await applyFilters(baseQuery.clone())
      // Alias participantid as id so the view can keep using users[i].id
      .select("participantid as id", "username", "role")
      .orderBy("participantid", "asc")
      .limit(pageSize)
      .offset(offset);

    res.render("users/users", {
      users,
      currentPage: safePage,
      totalPages,
      search_name,
      isSearching,
      error_message: ""
    });
  } catch (err) {
    console.error("Error loading users:", err);

    res.render("users/users", {
      users: [],
      currentPage: 1,
      totalPages: 0,
      search_name,
      isSearching,
      error_message: "There was a problem loading user data."
    });
  }
});

app.get("/editUser/:id", async (req, res) => {
  const participantId = req.params.id;

  try {
    const user = await knex("users")
      .where("participantid", participantId)
      .first();

    if (!user) {
      return res.status(404).render("users/edituser", {
        participantId,
        formData: {},
        error_message: "User not found."
      });
    }

    const formData = {
      username: user.username || "",
      role: user.role || ""
      // password is not sent to the view
    };

    res.render("users/edituser", {
      participantId,
      formData,
      error_message: ""
    });
  } catch (err) {
    console.error("Error loading user for edit:", err);
    res.status(500).render("users/edituser", {
      participantId,
      formData: {},
      error_message: "There was a problem loading this user."
    });
  }
});

app.post("/editUser/:id", async (req, res) => {
  const participantId = req.params.id;

  const {
    username,
    role,
    password,
    passwordConfirm
  } = req.body;

  if (!username) {
    return res.status(400).render("users/edituser", {
      participantId,
      formData: req.body || {},
      error_message: "Username is required."
    });
  }

  if (!role) {
    return res.status(400).render("users/edituser", {
      participantId,
      formData: req.body || {},
      error_message: "Role is required."
    });
  }

  if (password && passwordConfirm && password !== passwordConfirm) {
    return res.status(400).render("users/edituser", {
      participantId,
      formData: req.body || {},
      error_message: "Password and confirmation do not match."
    });
  }
    const hashedPassword = await bcrypt.hash(password, 10);


  try {
    const user = await knex("users")
      .where("participantid", participantId)
      .first();

    if (!user) {
      return res.status(404).render("users/edituser", {
        participantId,
        formData: req.body || {},
        error_message: "User not found."
      });
    }

    const updates = {
      username,
      role
    };

    if (password) {
      // TODO: hash password if needed
      updates.password = hashedPassword;
    }

    await knex("users")
      .where("participantid", participantId)
      .update(updates);

    res.redirect("/users?success=1");
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).render("users/edituser", {
      participantId,
      formData: req.body || {},
      error_message: "There was a problem saving this user."
    });
  }
});

app.post("/deleteUser/:id", async (req, res) => {
  const participantId = req.params.id;

  try {
    // Delete from users table by participantid
    const deletedCount = await knex("users")
      .where("participantid", participantId)
      .del();

    if (deletedCount === 0) {
      console.warn(`Delete user: no user found with participantid ${participantId}`);
      return res.redirect("/users?error=User+not+found");
    }

    res.redirect("/users?success=User+deleted");
  } catch (err) {
    console.error("Error deleting user:", err);
    res.redirect("/users?error=Error+deleting+user");
  }
});




app.get("/admin/users/add", async (req, res) => {
  try {
    res.render("users/adduser", {
      error_message: null,
      formData: {}
    });
  } catch (err) {
    console.error("Error rendering add user form:", err);
    res.status(500).send("Server error");
  }
});



app.post("/admin/users/add", async (req, res) => {
  const {
    // participant fields from the form
    participantemail,
    participantfirstname,
    participantlastname,
    participantdob,
    participantphone,
    participantcity,
    participantstate,
    participantzip,
    participantschooloremployer,
    participantfieldofinterest,
    // user fields from the form
    username,
    role,
    password,
    passwordConfirm
  } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  // Basic validation
  if (!participantemail || !participantfirstname || !participantlastname) {
    return res.status(400).render("users/adduser", {
      error_message: "Email, first name, and last name are required.",
      formData: req.body || {}
    });
  }

  if (password && passwordConfirm && password !== passwordConfirm) {
    return res.status(400).render("users/adduser", {
      error_message: "Password and confirmation do not match.",
      formData: req.body || {}
    });
  }

  // Normalize field of interest to allowed values
  let cleanField = participantfieldofinterest || null;
  const allowedFields = ["stem", "arts", "both"];
  if (cleanField && !allowedFields.includes(cleanField)) {
    cleanField = null;
  }

  // Map user role to participantrole
  let participantRoleFromUser = null;
  if (role === "admin") {
    participantRoleFromUser = "admin";
  } else if (role === "user" || role === "viewer") {
    participantRoleFromUser = "participant";
  }

  try {
    await knex.transaction(async trx => {
      // 1. Find existing participant by email
      let participant = await trx("participant")
        .where("participantemail", participantemail)
        .first();

      let participantId;

      if (!participant) {
        // 2. Create a new participant
        const [insertedParticipant] = await trx("participant").insert(
          {
            participantemail,
            participantfirstname,
            participantlastname,
            participantdob: participantdob || null,
            participantrole: participantRoleFromUser || null,
            participantphone: participantphone || null,
            participantcity: participantcity || null,
            participantstate: participantstate || null,
            participantzip: participantzip || null,
            participantschooloremployer: participantschooloremployer || null,
            participantfieldofinterest: cleanField || null
          },
          ["participantid"]
        );

        participantId = insertedParticipant.participantid;
      } else {
        // 3. Update existing participant if needed
        participantId = participant.participantid;

        const updates = {};

        // Always sync required fields
        if (participant.participantfirstname !== participantfirstname) {
          updates.participantfirstname = participantfirstname;
        }
        if (participant.participantlastname !== participantlastname) {
          updates.participantlastname = participantlastname;
        }

        // Optional fields only if provided
        if (participantdob && participant.participantdob !== participantdob) {
          updates.participantdob = participantdob;
        }
        if (participantphone && participant.participantphone !== participantphone) {
          updates.participantphone = participantphone;
        }
        if (participantcity && participant.participantcity !== participantcity) {
          updates.participantcity = participantcity;
        }
        if (participantstate && participant.participantstate !== participantstate) {
          updates.participantstate = participantstate;
        }
        if (participantzip && participant.participantzip !== participantzip) {
          updates.participantzip = participantzip;
        }
        if (
          participantschooloremployer &&
          participant.participantschooloremployer !== participantschooloremployer
        ) {
          updates.participantschooloremployer = participantschooloremployer;
        }
        if (cleanField && participant.participantfieldofinterest !== cleanField) {
          updates.participantfieldofinterest = cleanField;
        }
        if (
          participantRoleFromUser &&
          participant.participantrole !== participantRoleFromUser
        ) {
          updates.participantrole = participantRoleFromUser;
        }

        if (Object.keys(updates).length > 0) {
          await trx("participant")
            .where("participantid", participantId)
            .update(updates);
        }
      }

      // 4. Make sure a user does not already exist for this participant
      const existingUser = await trx("users")
        .where("participantid", participantId)
        .first();

      if (existingUser) {
        throw new Error("A user already exists for this participant.");
      }

      // 5. Insert user row
      // TODO: hash the password before saving and store that hash instead
      await trx("users").insert({
        participantid: participantId,
        username: username || null,
        role: role || null,
        password: hashedPassword || null
      });
    });

    // Success
    res.redirect("/admin/users?success=1");
  } catch (err) {
    console.error("Error adding user:", err);
    res.status(500).render("users/adduser", {
      error_message: err.message || "Error adding user.",
      formData: req.body || {}
    });
  }
});

// The role is hardcoded to 'user' as requested.
app.post('/register-user', async (req, res) => {
    const { username, password, participantId, email } = req.body;
    
    // Basic validation
    if (!username || !password || !participantId) {
        return res.status(400).json({ message: "Missing required fields." });
    }

    // Hash the password (using bcrypt as an example, ensure you have it installed)
    // const hashedPassword = await bcrypt.hash(password, 10); 
    // For this example, we'll use a placeholder for the hash:
    const hashedPassword = `HASHED_${password}`; 
    
    try {
        // Ensure username is unique
        const existingUsername = await knex('users')
            .where('username', username)
            .first();

        if (existingUsername) {
            return res.status(409).json({ message: "Username already taken." });
        }

        // Perform the registration transaction
        await knex('users').insert({
            // NOTE: The primary key (id) in the users table is set 
            // to the participantid, fulfilling the linking requirement.
            id: participantId, 
            username: username,
            password_hash: hashedPassword, // Use your actual column name
            role: 'user', 
            email: email // Store email for completeness
        });

        res.status(200).json({ 
            message: "User account created successfully.", 
            redirectTo: '/login' 
        });

    } catch (err) {
        console.error("Database error during user registration:", err);
        res.status(500).json({ message: "Failed to register user account." });
    }
});

app.get("/register", (req, res) => {
    res.render("register");
});

// app.post('/register', async (req, res) => {
//     const { username, password, confirmPassword } = req.body;

//     try {
//         // Validation
//         if (!username || !password || !confirmPassword) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'All fields are required.' 
//             });
//         }

//         if (password !== confirmPassword) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Passwords do not match.' 
//             });
//         }

//         if (password.length < 6) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Password must be at least 6 characters long.' 
//             });
//         }

//         // Check if username already exists
//         const existingUser = await knex.raw(
//             'SELECT * FROM users WHERE username = ?',
//             [username]
//         );

//         if (existingUser.rows.length > 0) {
//             return res.status(400).json({ 
//                 success: false, 
//                 message: 'Username already exists.' 
//             });
//         }

//         // Hash the password
//         const hashedPassword = await bcrypt.hash(password, 10);

//         // Insert new owner into database
//         await knex.raw(
//             'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
//             [username, hashedPassword, 'manager']
//         );

//         console.log(` New manager registered: ${username}`);

//         return res.status(200).json({ 
//             success: true, 
//             message: 'Manager registration successful!', 
//             redirectTo: '/login' 
//         });

//     } catch (error) {
//         console.error('Manager registration error:', error);
//         return res.status(500).json({ 
//             success: false, 
//             message: 'An error occurred during registration.' 
//         });
//     }
// });

app.get("/teapot", (req, res) => {
    // Renders the teapot.ejs file located in the views folder with 418 status code
    res.status(418).render("teapot"); 
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});