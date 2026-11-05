# CampusCare - Campus Complaint Management System

Students report campus maintenance problems (with photos) and track them to resolution. Administrators monitor, prioritise and resolve every complaint. Black + pink theme, real SQLite database, session-based auth.

## Run it locally

Requires **Node.js 18+**.

```bash
npm install
npm run seed     # development only: creates demo accounts and sample complaints
npm start        # http://localhost:3000
```

Optional environment variables: `PORT` (default 3000), `SESSION_SECRET` (set a long random value outside development).

## Development login credentials (created by `npm run seed`)

| Role | Login | Password |
|---|---|---|
| Administrator (`#/admin-login`) | `admin` | `Admin@123` |
| Student | `REG2023CS001` or `priya@student.edu` | `Student@123` |
| Student | `REG2023ME014` or `arjun@student.edu` | `Student@123` |

`npm run seed` **deletes all existing data** and refuses to run when `NODE_ENV=production`. Credentials exist only in `seed.js`, never in frontend code.

## Folder structure

```
server.js            Express app, all API routes, security middleware
db.js                SQLite connection + schema (5 tables)
seed.js              Development seed script
public/index.html    App shell
public/css/style.css Black + pink theme, responsive layout
public/js/app.js     Frontend (hash-routed SPA, all 14 pages)
uploads/             Uploaded photos (created automatically, served only to owner/admin)
data/complaints.db   SQLite file (created automatically)
```

## Pages

Landing, Student Registration, Student Login, Admin Login, Student Dashboard, Submit Complaint, My Complaints, Complaint Details & Tracking, Notifications, Admin Dashboard, Admin Manage Complaints, Admin Complaint Details, Admin Reports (with print and CSV export), Profile & Settings.

## Database tables

`Users`, `Admins`, `Complaints`, `Complaint_Status_History`, `Notifications` (see `db.js`).

## API routes

Auth: `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/admin-login`, `POST /api/auth/logout`, `GET /api/auth/me`
Profile: `PUT /api/profile`, `PUT /api/profile/password`
Meta: `GET /api/meta`
Student: `GET /api/student/stats`, `GET /api/complaints?q=&status=`, `POST /api/complaints` (multipart), `GET /api/complaints/:id`
Notifications: `GET /api/notifications`, `GET /api/notifications/unread`, `POST /api/notifications/read-all`, `POST /api/notifications/:id/read`
Admin: `GET /api/admin/stats`, `GET /api/admin/complaints?q=&category=&department=&priority=&status=`, `GET|PUT /api/admin/complaints/:id`, `GET /api/admin/reports?from=&to=`, `GET /api/admin/reports/csv?from=&to=`
Images: `GET /uploads/:file` (owner or admin only)

## Security measures

bcrypt password hashing; server-side validation on every input; parameterised SQL only; role-based middleware (students can only read their own complaints, admin routes require an admin session); session fixation protection (session regenerated on login); HttpOnly + SameSite cookies; login rate limiting (10 failures / 15 min / IP); uploads limited to JPG/PNG up to 5 MB, checked by MIME type, extension and file signature, stored under random names; output escaped in the UI; CSV export neutralises spreadsheet formulas.

For a production deployment you would additionally add HTTPS with `cookie.secure`, a persistent session store, and CSRF tokens.

## Demo walkthrough

1. Log in as a student, submit a complaint with a photo, then see it on the dashboard and tracking page.
2. Log in as admin (use a second browser/profile), open the complaint, change status/priority and add remarks.
3. Return to the student: the status, timeline, remarks and a new notification appear.
4. Open Admin > Reports, filter by date, print or export CSV.
