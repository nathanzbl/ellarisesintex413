# Ella Rises – INTEX Fall 2025

> A full-stack analytics platform that helps Ella Rises manage participants, events, surveys, milestones, and donations, and measure long-term STEAM impact.

---

## 🚀 Live Deployment

| Item | Value |
|------|-------|
| **URL** | `<ellarises.byuisresearch.com>` |

### Manager Login

| Field | Value |
|-------|-------|
| Username | `EllaJohnson` |
| Password | `admin12` |

### Viewer Login

| Field | Value |
|-------|-------|
| Username | `MateoHill` |
| Password | `admin12` |

### User Login

| Field | Value |
|-------|-------|
| Username | `"BrooklyAllen"` |
| Password | `user12` |

### Other Requirements

- ✅ HTTPS enabled (AWS ACM)
- ✅ Custom DNS domain/subdomain
- ✅ HTTP 418 route: `/teapot`

---

## 📁 Project Structure

```
project-root/
├── src/
│   ├── server.js
│   ├── routes/
│   ├── controllers/
│   ├── models/
│   └── middleware/
├── views/
│   ├── layouts/
│   ├── partials/
│   ├── participants/
│   ├── events/
│   ├── surveys/
│   ├── milestones/
│   ├── donations/
│   └── dashboard/
├── public/
│   ├── css/
│   ├── js/
│   └── images/
└── sql/
    ├── create_tables.sql
    ├── insert_data.sql
    ├── normalization_3nf.xlsx
    └── erd.pdf
```

---

## 💻 Local Setup

### Requirements

- Node.js 18+
- PostgreSQL 15+
- npm

### Install

```bash
npm install
cp .env.example .env
```

> Add DB credentials to `.env`

### Database

```bash
psql -U <user> -d <db> -f sql/create_tables.sql
psql -U <user> -d <db> -f sql/insert_data.sql
```

### Run

```bash
npm start
```

**Local URL:** http://localhost:3000/

---

## 🔐 Roles & Permissions

### Manager

- Full CRUD for Participants, Events, Surveys, Milestones, Donations
- Dashboard access
- Admin tools

### Common User

- Read-only access
- Dashboard access

### Public

- Donor landing page

### Security

- `bcrypt`
- `express-session`
- CSRF protection
- Input sanitization
- `helmet` (optional)

---

## 🧩 Core Features

### Participants

- CRUD operations
- Demographics tracking
- Milestone assignments
- Linked survey history

### Events

- CRUD operations
- Event type classification
- Effectiveness metrics

### Surveys

- Satisfaction, usefulness, instructor, recommendation, overall score
- Linked to event + participant
- CRUD operations
- Comment storage

### Milestones

- Admin-defined
- Many-per-participant
- Used for long-term impact metrics

### Donations

- CRUD operations
- Donor info
- Public donor support page

### Dashboard

- Built with **Tableau/Chart.js**
- STEAM graduation rate
- STEAM job placement rate
- Event effectiveness
- Filters for demographics + event type
- Clean SWD-style visuals

---

## ☁️ AWS Deployment (IS 404 Requirements)

| Requirement | Status |
|-------------|--------|
| Deployed on AWS | ✔️ |
| Managed RDS PostgreSQL | ✔️ |
| HTTPS (ACM) | ✔️ |
| Custom Domain (Route 53) | ✔️ |
| HTTP 418 route | ✔️ |
| No Learner Lab | ✔️ |

### Stack Includes

- Elastic Beanstalk or EC2
- RDS PostgreSQL
- Route 53
- ACM SSL
- Optional S3 for static assets

---

## 📊 Data & Analytics (IS 415)

### Python Exploratory Analysis

**Location:** `analysis/ella_rises_exploration.ipynb`

**Includes:**

- Dataset overview
- Cleaning
- Univariate analysis (4+ variables)
- Bivariate analysis (4+ relationships)
- Insights after each step

### Key Insights

1. Event type strongly influences milestone attainment
2. Recommendation score is the strongest predictor
3. STEAM programming → higher milestone progress
4. Instructor quality → satisfaction → milestones
5. Demographic differences show varying outcomes

---

## 🖥️ Presentation Materials

**Location:** `/presentation/`

- Slide deck
- Two SWD-compliant charts
- Narrative structure: problem → insights → action
- Dashboard demo
- Four short walkthrough videos

---

## 🧪 TA Grading Guide

1. Open live site
2. Log in as admin
3. Test CRUD for all entities
4. Verify common user read-only permissions
5. Test dashboard filters
6. Confirm HTTPS + custom domain
7. Visit `/teapot` for HTTP 418
8. Review SQL schema + inserts
9. Open normalization spreadsheet + ERD
10. Watch the videos

> **Everything required for grading is included in the ZIP.**

---

## 👥 Team

*Add your names here.*

---

## 🛠️ Tech Stack

| Category | Technologies |
|----------|--------------|
| **Backend** | Node.js, Express |
| **Templating** | EJS |
| **Database** | PostgreSQL, Knex |
| **Visualization** | Chart.js, Tableau |
| **Analytics** | Python (Pandas, NumPy, Matplotlib, Seaborn) |
| **Cloud** | AWS (EB/EC2, RDS, Route 53, ACM) |
