# Banter & Brats - Chat Application

## Overview
Banter & Brats is an 18+ community chat application built with Node.js and Express. It features rooms, DMs, reactions, leaderboards, themes, and profile customization.

## Project Structure
- `server.js` - Main Express server with Socket.IO for real-time chat
- `database.js` - Database utilities for SQLite (local dev) and PostgreSQL (production)
- `public/` - Frontend static assets (app.js, theme-init.js)
- `index.html` - Main HTML entry point
- `styles.css` - Application styles
- `migrations/` - PostgreSQL migration files
- `scripts/` - Development and testing scripts

## Tech Stack
- **Backend**: Node.js 20, Express 5
- **Database**: PostgreSQL (primary), SQLite (local fallback)
- **Real-time**: Socket.IO
- **Auth**: bcrypt for password hashing, express-session
- **Other**: Helmet (security), multer (file uploads), nodemailer (emails)

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string (auto-configured by Replit)
- `SESSION_SECRET` - Session encryption key (configured as secret)
- `PORT` - Server port (set to 5000)
- `SQLITE_PATH` - Optional local SQLite path

## Running the App
- **Development**: `npm run dev` (enables LOCAL_DEV mode)
- **Production**: `npm start`

## Recent Changes
- 2026-01-28: Initial Replit setup, configured PostgreSQL, set PORT to 5000

## Notes
- The app uses both SQLite and PostgreSQL - SQLite for local development, PostgreSQL for production
- Migrations in `migrations/` folder are for PostgreSQL schema
