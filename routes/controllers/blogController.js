import {Blog} from "../../models/blogModel.js";

// Get all blogs
export const getAllBlogs = async (req,res) =>
{
    try{
        const blogs = await Blog.getAll(); // Get all blogs
        res.status(200).json(blogs); // Return the blogs in JSON format
    } catch (err){
        console.error("Error fetching blogs:", err); // Log the error
        res.status(500).json({error: "Internal server error"}); // Return an error message
    }
};

// Get a specific blog by id

export const getBlogById = async (req,res) =>
{
    const {id} = req.params; // Get the id from the request parameters 
    try 
    {
        const blog = await Blog.getById(id);
        if(!blog)
        {
            return res.status(404).json({error: "Blog not found"}); // Return an error message if the blog is not found
        }
        res.status(200).json(blog); // Return the blog in JSON format
    }
    catch (err)
    {
        console.error("Error fetching blog:", err); // Log the error
        res.status(500).json({error:"Internal server error"}) // Return an error message
    }
};

// Create a new blog

 export const createBlog = async (req,res) =>
 {
    const {user_id, title, content, image_url} = req.body; // Get the user_id, title, content, and image_url from the request body
    try
    {
        const newBlog = await Blog.create ({ user_id, title, content, image_url}) // Create a new blog
        res.status(201).json(newBlog); // Return the new blog in JSON format
    }
    catch (err)
    {
        console.error("Error creating blog:", err); // Log the error
        res.status(500).json({error: "Internal server error"}); // Return an error message  
    }
 };

 export const updateBlog = async (req,res) =>
 {
    const {id} = req.params; // Get the id from the request parameters
    const {title, content, image_url} = req.body; // Get the title, content, and image_url from the request body
    try
    {
        const updatedBlof = await Blog.update(id, {title, content, image_url}) // Update the blog   
        if(!updatdBlog)
        {
            return res.status(404).json({error: "Blog not found"}); // Return an error message if the blog is not found
        }
        res.status(200).json(updatedBlog); // Return the updated blog in JSON format
    } catch(err)
    {
        console.error("Error updating blog:", err); // Log the error
        res.status(500).json({error: "Internal server error"}); // Return an error message  
    }
 }

 export const deleteBlog = async (req,res) =>
 {
    const {id} = req.params; // Get the id from the request parameters
    try
    {
        const deleted = await Blog.delete(id); // Delete the blog
        if(!deleted)
        {
            return res.status(404).json({error: "Blog not found"}); // Return an error message if the blog is not found
        }
        res.status(200).json({message: "Blog deleted"}); // Return a success message
    }
    catch(err)
    {
        console.error("Error deleting blog:", err); // Log the error
        res.status(500).json({error: "Internal server error"}); // Return an error message
    }
 }
