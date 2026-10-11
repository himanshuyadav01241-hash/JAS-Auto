# JAS Auto Detailing website

Setup (Node 20.6+):
1. `npm install`
2. `cp .env.example .env`, then `npm run hash -- "YourLongPassword"` and paste the result into ADMIN_HASH; set SECRET to 32+ random characters.
3. `npm start`, open http://localhost:3000 (site) and /admin (dashboard).

Deploy: any Node host (Render, Railway, a VPS). Put it behind HTTPS (the host usually does this) and keep NODE_ENV=production so cookies are Secure.
Back up `data.json` regularly: it holds your content and bookings.
