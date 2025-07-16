import { Schema, model } from 'mongoose';

const tokenBlacklistSchema = new Schema(
  {
    jti: { type: String, required: true, unique: true },
    userId: { type: Schema.Types.ObjectId, required: true },
    expireAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  }
);

// Creates a TTL (Time-To-Live) Index. Document will be removed automatically after expiration.
tokenBlacklistSchema.index({ expireAt: 1 }, { expireAfterSeconds: 0 });
tokenBlacklistSchema.index({ jti: 1 });

const TokenBlacklist = model('TokenBlacklist', tokenBlacklistSchema);

export default TokenBlacklist;
