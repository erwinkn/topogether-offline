/* Use via `node -r scripts/env.js` */
require('dotenv').config({ path: `${__dirname}/../.env` });

// NOTE: in production you probably want to add ?ssl=true to force SSL usage.
process.env.ROOT_DATABASE_URL = `postgres://postgres:postgres@${process.env.DATABASE_HOST}:${process.env.DATABASE_PORT}/postgres`;
process.env.DATABASE_URL = `postgres://${process.env.DATABASE_OWNER}:${process.env.DATABASE_OWNER_PASSWORD}@${process.env.DATABASE_HOST}:${process.env.DATABASE_PORT}/${process.env.DATABASE_NAME}`;
process.env.SHADOW_DATABASE_URL = `postgres://${process.env.DATABASE_OWNER}:${process.env.DATABASE_OWNER_PASSWORD}@${process.env.DATABASE_HOST}:${process.env.DATABASE_PORT}/shadow`;