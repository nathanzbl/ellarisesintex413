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
- Input sanitization

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
| HTTPS (CertBot) | ✔️ |
| Custom Domain (Route 53) | ✔️ |
| HTTP 418 route | ✔️ |
| No Learner Lab | ✔️ |

### Stack Includes

- EC2
- RDS PostgreSQL
- Route 53


---



