import { Schema, model } from 'mongoose';

const tokenBlacklistSchema = new Schema(
  {
    token: String,
    userId: Schema.Types.ObjectId,
    expireAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: { createdAt: true, updatedAt: false }
  }
);

// Creates a TTL (Time-To-Live) Index. By default this is null, but when set, the DB will remove the document automatically after expiration.
tokenBlacklistSchema.index({ expireAt: 1 }, { expireAfterSeconds: 0 });

const TokenBlacklistlist = model('TokenBlacklist', tokenBlacklistSchema);

export default TokenBlacklistlist;
