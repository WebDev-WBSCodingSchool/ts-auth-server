import { Schema, model } from 'mongoose';

const blogPostSchema = new Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true
    },
    content: {
      type: String,
      required: true
    }
  },
  {
    timestamps: { createdAt: true, updatedAt: false }
  }
);

const BlogPost = model('BlogPost', blogPostSchema);

export default BlogPost;
