import express from "express";
import {getAllBlogs, createBlog, getBlogById, updateBlog, deleteBlog} from "./controllers/blogController.js"

const router = express.Router();

// Get all blogs
router.get("/", getAllBlogs);

// Create a specific blog by id

router.get("/:id", getBlogById);

// Create a blog

router.post("/", createBlog);

// Update a blog

router.put("/:id", updateBlog); 

// Delete a blog

router.delete("/:id", deleteBlog); 
export default router; // Export the router to use it in the main file