const mongoose = require('mongoose');

let mongoConnected = false;

function isMongoConfigured() {
  return Boolean(process.env.MONGODB_URI);
}

async function connectMongo() {
  if (!isMongoConfigured()) return null;

  mongoose.set('strictQuery', true);

  const uri = process.env.MONGODB_URI;
  if (!uri) return null;

  await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 10000,
  });

  mongoConnected = true;

  return mongoose.connection;
}

module.exports = {
  connectMongo,
  isMongoConfigured,
  isMongoConnected: () => mongoConnected && mongoose.connection?.readyState === 1,
};

