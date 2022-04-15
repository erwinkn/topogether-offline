const pg = require('pg');
const { run, sleep } = require('./_utils');
require('./env');

run(async () => {
  const {
    DATABASE_AUTHENTICATOR,
    DATABASE_AUTHENTICATOR_PASSWORD,
    DATABASE_OWNER,
    DATABASE_OWNER_PASSWORD,
    DATABASE_VISITOR,
    DATABASE_NAME,
    ROOT_DATABASE_URL,
  } = process.env;
  
  
  const pool = new pg.Pool({
    connectionString: ROOT_DATABASE_URL
  });
  
  pool.on("error", (err) => {
    // Ignore
    console.log(
      "An error occurred whilst trying to talk to the database: " + err.message
    );
  });

  
  // Wait for PostgreSQL to come up
  let attempts = 0;
  while (true) {
    try {
      await pool.query('select true as "Connection test";');
      break;
    } catch (e) {
      if (e.code === "28P01") {
        throw e;
      }
      attempts++;
      if (attempts <= 30) {
        console.log(
          `Database is not ready yet (attempt ${attempts}): ${e.message}`
        );
      } else {
        console.log(`Database never came up, aborting :(`);
        process.exit(1);
      }
      await sleep(1000);
    }
  }
  
  const client = await pool.connect();

  try {
    await client.query(`DROP DATABASE IF EXISTS ${DATABASE_NAME};`);
    await client.query(`DROP DATABASE IF EXISTS shadow;`);
    await client.query(`DROP ROLE IF EXISTS ${DATABASE_VISITOR};`);
    await client.query(`DROP ROLE IF EXISTS ${DATABASE_AUTHENTICATOR};`);
    await client.query(`DROP ROLE IF EXISTS ${DATABASE_OWNER};`);

    // This is the root role for the database
    await client.query(
      // IMPORTANT: don't grant SUPERUSER in production, we only need this so we can load the watch fixtures!
      `CREATE ROLE ${DATABASE_OWNER} WITH LOGIN PASSWORD '${DATABASE_OWNER_PASSWORD}' SUPERUSER;`
    );

    // This is the no-access role that PostGraphile will run as by default
    await client.query(
      `CREATE ROLE ${DATABASE_AUTHENTICATOR} WITH LOGIN PASSWORD '${DATABASE_AUTHENTICATOR_PASSWORD}' NOINHERIT;`
    );

    // This is the role that PostGraphile will switch to (from ${DATABASE_AUTHENTICATOR}) during a GraphQL request
    await client.query(`CREATE ROLE ${DATABASE_VISITOR};`);

    // This enables PostGraphile to switch from ${DATABASE_AUTHENTICATOR} to ${DATABASE_VISITOR}
    await client.query(
      `GRANT ${DATABASE_VISITOR} TO ${DATABASE_AUTHENTICATOR};`
    );
    
    await client.query(`CREATE DATABASE ${DATABASE_NAME};`);
    await client.query(`CREATE DATABASE shadow;`);
    // Those two have been taken from the heroku-setup.template
    // TODO: check that they are correct both for dev and production
    await client.query(`REVOKE ALL ON DATABASE ${DATABASE_NAME} FROM PUBLIC`);
    await client.query(`GRANT CONNECT ON DATABASE ${DATABASE_NAME} TO ${DATABASE_AUTHENTICATOR}`)

    console.log("--> Database is good to go!");

  } finally {
    await client.release();
  }
  await pool.end();
});

