import mongoose from 'mongoose';
const MONGO_URI = process.env.MONGO_URI || '';

try {
  await mongoose.connect(MONGO_URI, { dbName: 'auth' });
  console.log('✅ Connected to MongoDB');
} catch (err) {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
}
