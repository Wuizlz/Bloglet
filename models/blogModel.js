import pg from "pg";
import env from "dotenv";

env.config(); // Load the environment variables
const Blogdb = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
Blogdb.connect(); // Connect to the PostgreSQL database

class Blog
{
    user_id;
    title;
    content;
    image_url;
    created_at;
    updated_at;
    constructor(user_id, title, content, image_url, created_at, updated_at)
    {
        user_id = this.user_id;
        title = this.title;
        content = this.content;
        image_url = this.image_url;
        created_at = this.created_at;
        updated_at = this.updated_at;
    }
    static async getAll()
    {
        const query = "SELECT * FROM blogs"; // SQL query to get all blogs
        const {rows} = await Blogdb.query(query); // Execute the query
        return rows; // Return the blogs
    }
}