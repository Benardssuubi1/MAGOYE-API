# Magoye Family API

Flask + PostgreSQL API deployed on Railway.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/ping | Health check |
| GET | /api/stats | Counts for all collections |
| GET | /api/updates | Get all updates |
| POST | /api/updates | Add an update |
| PATCH | /api/updates/:id | Edit an update |
| DELETE | /api/updates/:id | Delete an update |
| GET | /api/members | Get all family members |
| POST | /api/members | Add a member |
| PATCH | /api/members/:id | Edit a member |
| DELETE | /api/members/:id | Delete a member |
| GET | /api/gallery | Get all photos |
| POST | /api/gallery | Add a photo |
| DELETE | /api/gallery/:id | Delete a photo |
| GET | /api/chat | Get messages |
| POST | /api/chat | Send a message |

## Auth
All requests need header: `X-API-Key: magoye-secret-2025`

## Deploy on Railway
1. Push this folder to GitHub
2. New project on railway.app → Deploy from GitHub
3. Add PostgreSQL plugin → DATABASE_URL is auto-set
4. Add env variable: API_SECRET_KEY=magoye-secret-2025
5. Deploy — done!
