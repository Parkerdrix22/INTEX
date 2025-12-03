
require('dotenv').config();

const knex = require("knex")({
    client: "pg",
    connection: {
        host: process.env.RDS_HOSTNAME || "awseb-e-qzuktehy2v-stack-awsebrdsdatabase-kjohppsz4ibe.cb8eie2ew4fz.us-east-2.rds.amazonaws.com",
        user: process.env.RDS_USERNAME || "intex2025",
        password: process.env.RDS_PASSWORD || "intex0403",
        database: process.env.RDS_DB_NAME || "ebdb",
        port: process.env.RDS_PORT || 5432,
        ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
    }
});

const eventId = process.argv[2];
const imagePath = process.argv[3];

if (!eventId || !imagePath) {
    console.error("Usage: node update_event_image.js <eventId> <imagePath>");
    process.exit(1);
}

knex('events')
    .where('eventid', eventId)
    .update({ eventimage: imagePath })
    .then(() => {
        console.log(`Updated event ${eventId} with image ${imagePath}`);
        process.exit(0);
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
