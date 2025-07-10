import type { RequestHandler } from 'express';
import type { z } from 'zod/v4';
import type { blogPostInputSchema, blogPostSchema } from '#schemas';
import { BlogPost } from '#models';

type BlogPostInputDTO = z.infer<typeof blogPostInputSchema>;
type BlogPostDTO = z.infer<typeof blogPostSchema>;

export const createBlogPost: RequestHandler<unknown, BlogPostDTO, BlogPostInputDTO> = async (
  req,
  res
) => {
  const newPostDoc = await BlogPost.create(req.body);
  const newPost = newPostDoc.toJSON<BlogPostDTO>({ versionKey: false });
  res.status(201).json(newPost);
};

export const getAllBlogPosts: RequestHandler<unknown, BlogPostDTO[], unknown> = async (
  req,
  res
) => {
  const posts = await BlogPost.find().lean<BlogPostDTO[]>().select('-__v').sort({ createdAt: -1 });
  res.status(200).json(posts);
};

export const getBlogPostById: RequestHandler<{ id: string }, BlogPostDTO, unknown> = async (
  req,
  res
) => {
  const post = await BlogPost.findById(req.params.id).lean<BlogPostDTO>().select('-__v');
  if (!post) {
    throw new Error('Post not found', { cause: { status: 404 } });
  }
  res.status(200).json(post);
};

export const updateBlogPost: RequestHandler<{ id: string }, BlogPostDTO, BlogPostInputDTO> = async (
  req,
  res
) => {
  const updated = await BlogPost.findByIdAndUpdate(req.params.id, req.body, { new: true })
    .lean<BlogPostDTO>()
    .select('-__v');
  if (!updated) {
    throw new Error('Post not found', { cause: { status: 404 } });
  }
  res.status(200).json(updated);
};

export const deleteBlogPost: RequestHandler<{ id: string }, { message: string }> = async (
  req,
  res
) => {
  const deleted = await BlogPost.findByIdAndDelete(req.params.id);
  if (!deleted) {
    throw new Error('Post not found', { cause: { status: 404 } });
  }
  res.status(200).json({ message: 'Blog post deleted successfully' });
};
