// testDatabaseConnection.js
require('dotenv').config();
const MongoClient = require('mongodb').MongoClient;

const uri = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true`;

const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function run() {
    try {
        await client.connect();
        console.log("Connected correctly to server");

        const db = client.db(process.env.MONGODB_DATABASE);
        const collections = await db.listCollections().toArray();
        console.log("Collections:", collections.map(col => col.name));
    } catch (err) {
        console.error("An error occurred connecting to MongoDB:", err);
    } finally {
        await client.close();
    }
}

run();
