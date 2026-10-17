# Portfolio API

Express and Mongoose API for the Sujeet Honnappagol portfolio. It provides the public contact endpoint and protected admin APIs. Contact messages are stored in MongoDB `sujeet_portfolio.contacts`.

## Requirements

- Node.js 20.11 or newer
- npm
- MongoDB Atlas or another reachable MongoDB instance

## Configure

Copy `.env.example` to `.env` and set `MONGODB_URI` to a private MongoDB connection string. Configure `CLIENT_ORIGIN` and `ADMIN_ORIGIN` to the frontend origins. The server explicitly selects the `sujeet_portfolio` database.

Create or reset the first admin account from this folder:

```sh
npm run setup-admin
```

Enter the admin email, then a new password of at least 14 characters at the masked terminal prompt. The setup script saves a bcrypt hash and generated session secret, never plaintext password. Keep `.env` private; it is excluded by `.gitignore`.

## Run and test

```sh
npm install
npm run dev
```

The API listens on `http://localhost:5000`. Check `GET /api/health` for API and database status. Run MongoDB-backed integration tests with:

```sh
npm test
```

## Endpoints

- `GET /api/health`
- `GET /api/projects` and `GET /api/projects/:id`
- `POST /api/contact`
- `POST /api/admin/login`, `/logout`, and `/me`
- `GET /api/admin/dashboard/stats`
- `GET /api/admin/contacts` and `/contacts/:id`
- `PATCH /api/admin/contacts/:id/status`
- `DELETE /api/admin/contacts/:id`

Admin endpoints use server-side authorization, short-lived HTTP-only cookies, CSRF/origin checks, and login rate limiting. For production, set secrets in the hosting provider's environment settings, configure exact frontend origins, and use HTTPS.