# mdt-api

Standalone MDT API for PRP/Qbox.

## Features

- Local JWT auth with bootstrap admin support
- Qbox-backed character and vehicle lookup
- MDT incidents, evidence, charges, announcements, notes, and flags
- Optional live-player bridge through `mdt-resource-api`
- Self-bootstrapping schema for easy Pterodactyl deployment

## Start

1. Copy `.env.example` to `.env`
2. Set database and JWT values
3. `npm install`
4. `npm run start`
