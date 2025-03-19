require('dotenv').config();
const express = require('express');
const cors = require("cors");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
require("dotenv").config()

const app = express();
app.use(cors());
app.use(express.json());

const databasePath = path.join(__dirname, 'jobs.db');
let database = null;


//database initialization function
const initializeDatabaseAndServer = async () => {
    try {
        database = await open({
            filename: databasePath,
            driver: sqlite3.Database,
        });
        app.listen(5001, () => {
            console.log('Server Running At http://localhost:5001/');
        });
    } catch (error) {
        console.error(`DB Error: ${error.message}`);
        process.exit(1);
    }
};
initializeDatabaseAndServer();

//password validate function
const validatePassword = (password) => /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/.test(password);

//user register as a job seeker or recruiter...
app.post('/register', async (req, res) => {
  try {
      const { name, email, password, role } = req.body;

      if (!name || !email || !password || !role) {
          return res.status(400).json({ error: "All fields are required" });
      }

      const checkTheEmail = `SELECT * FROM user WHERE email = ?`;
      let userData = await database.get(checkTheEmail, [email]);

      if (userData) {
          return res.status(400).json({ error: "User Already Exists" });
      }

      if (!validatePassword(password)) {
          return res.status(400).json({ error: "Weak password! Use at least 6 characters with a number." });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const postNewUserQuery = `INSERT INTO user (name, email, password, role) VALUES (?, ?, ?, ?);`;
      await database.run(postNewUserQuery, [name, email, hashedPassword, role]);

      res.json({ message: "User Created Successfully" });
  } catch (error) {
      res.status(500).json({ error: error.message });
  }
});


//user login in page
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const selectUserQuery = `SELECT * FROM user WHERE email = ?`;
        let dbUser = await database.get(selectUserQuery, [email]);

        if (!dbUser) {
            return res.status(400).send("Invalid User");
        }

        const isPasswordMatch = await bcrypt.compare(password, dbUser.password);
        if (isPasswordMatch) {
            const token = jwt.sign({ id: dbUser.id, role: dbUser.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
            res.status(200).json({ message: "Login Successful", token });
        } else {
            res.status(400).send("Invalid Password");
        }
    } catch (error) {
        res.status(500).send(error.message);
    }
});

//passwrod authenticated middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
      return res.status(401).json({ error: "Invalid JWT Token" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (error, payload) => {
      if (error) {
          return res.status(401).json({ error: "Invalid JWT Token" });
      }
      req.user = payload; 

      next();
  });
}


//user or recruiter check their profile
app.get("/profile", authenticateToken, async(req, res) => {
    try {
        const userId = req.user.id
        const getUserQuery = `
          SELECT id, name, email, role FROM user WHERE id = ?
        `;
        const user = await database.all(getUserQuery, [userId]);

        if(!user){
            return res.status(400).json({error: "User Not Found"})
        }
        res.status(200).json(user)
    } catch (error) {
        res.status(500)
        res.send("Internal Server Error")
    }
})


//user or recruiter update their profile
app.put("/profile", authenticateToken, async(req, res) => {
    try {
        const userId = req.user.id;
        const {name, email, password} = req.body;

        if(!name && !email && !password) {
            return res.status(400).json({error: "Provide Updates"});
        }

        let updateFields = [];
        let params = []

        if(name){
            updateFields.push("name = ?")
            params.push(name)
        }

        if(email){
            updateFields.push("email = ?")
            params.push(email)
        }

        if(password){
            if(!validatePassword(password)){
                return res.status(400).json({error: "Use Atleast 6 Characters with number"})
            }
            const hashedPassword = await bcrypt.hash(password, 10)
            updateFields.push("password = ? ")
            params.push(hashedPassword)
        }

        params.push(userId);
        const updateUserQuery = `UPDATE user SET ${updateFields.join(", ")} WHERE id = ?`;
        await database.run(updateUserQuery, params);

        res.status(200).json({ message: "Profile updated successfully" });



    } catch (error) {
        res.status(500).json({ error: "Server Error" });
    }
})


//only recruiter post jobs in page
app.post("/jobs/post", authenticateToken, async (req, res) => {
  try {
      if (!req.user || req.user.role !== "recruiter") {
          return res.status(403).json({ error: "Only recruiters can post jobs" });
      }

      const { title, companyName, location, salary, jobType, description, aboutCompany, skill } = req.body;
      
      if (!title || !companyName || !location || !salary || !jobType || !description || !aboutCompany || !skill) {
          return res.status(400).json({ error: "All fields are required" });
      }

      const postJobQuery = `INSERT INTO jobs 
          (title, company_name, location, salary, job_type, description, about_company, skill, recruiter_id) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`;
      
      await database.run(postJobQuery, [title, companyName, location, salary, jobType, description, aboutCompany, skill, req.user.id]);
      
      res.status(201).json({ message: "Job Successfully Posted" });
  } catch (error) {
      console.error("Post Job Error:", error);
      res.status(500).json({ error: "Internal Server Error" });
  }
});

//user or recruiter seen all jobs in page
app.get("/jobs", async(req, res) => {
    
  try {
      const { page, limit } = req.query;
      
      let pageNum = parseInt(page) || 1;
      let pageLimit = parseInt(limit) || 5;
      let offset = (pageNum - 1) * pageLimit;

      const getJobsQuery = `SELECT * FROM jobs LIMIT ? OFFSET ?`;
      const jobsList = await database.all(getJobsQuery, [pageLimit, offset]);
      res.status(200)
      res.json({
        page: pageNum,
        limit: pageLimit,
        jobs: jobsList
      }) ;
  } catch (error) {
      res.status(500).json({ error: error.message }); 
  }
});


//job search with requirements 
app.get("/jobs/search", async(req, res)=>{
    try {
        
        const {title, jobType, companyName, location, skill} = req.body

        let query = "SELECT * FROM jobs WHERE";
        let params = [];
        let condition = [];


        if(title){
            condition.push(" title LIKE ? ")
            params.push(`%${title}%`);
        }

        if(companyName){
            condition.push(" company_name LIKE ? ")
            params.push(`%${companyName}%`);
        }

        if(jobType){
            condition.push(" job_type LIKE ? ")
            params.push(`%${jobType}%`);
        }

        if(location){
            condition.push(" location LIKE ? ")
            params.push(`%${location}%`);
        }

        if(skill){
            condition.push(" skill LIKE ? ")
            params.push(`%${skill}%`);
        }

        query += condition.join(" OR ");

        const jobs = await database.all(query, params);
        res.json({ jobs })

    } catch (error) {
        res.status(500);
        res.json({error: "Somnething Went Wrong"})
    }
})


//job filter with requirements
app.get("/jobs/filter", async(req, res) => {
    try {
        const {jobType, companyName, location, minSalary, maxSalary, skill, recently, page, limit } = req.body

        let query = "SELECT * FROM jobs WHERE 1 = 1"
        let params = [];

        if (jobType){
            query += " AND job_type LIKE ?";
            params.push(`%${jobType}%`);
        }

        if (companyName){
            query += " AND company_name LIKE ?";
            params.push(`%${companyName}%`);
        }

        if (location){
            query += " AND location LIKE ?";
            params.push(`%${location}%`);
        }

        if (minSalary){
            query += " AND salary >= ?";
            params.push(minSalary);
        }

        if (maxSalary){
            query += " AND salary <= ?";
            params.push(maxSalary);
        }

        if(skill){
            query += " AND skill LIKE ?";
            params.push(`%${skill}%`)
        }

        if(recently === "true"){
           query += " ORDER BY created_at DESC"
        }

        let pageNum = parseInt(page) || 1;
        let pageLimit = parseInt(limit) || 10;
        let offset = (pageNum - 1) * pageLimit;

        query += ` LIMIT ? OFFSET ?`;
        params.push(pageLimit, offset)
        

        const jobs = await database.all(query, params)
        res.json({jobs})


  
    } catch (error) {
        console.log(error)
        res.status(500)
        res.json({error: "Something Went Wrong"})
    }
})


//show details of a single job
app.get("/jobs/:id", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const jobId = req.params.id;

        const getJobDetailsQuery = `
          SELECT jobs.*,
          CASE 
            WHEN job_applications.user_id IS NOT NULL THEN 'Applied'
            ELSE 'Not Applied'
          END AS application_status
          FROM jobs
          LEFT JOIN job_applications
          ON jobs.id = job_applications.job_id AND job_applications.user_id = ?
          WHERE jobs.id = ?
        `;

        const jobDetails = await database.get(getJobDetailsQuery, [userId, jobId]);

        if (!jobDetails) {
            res.status(404).json({ error: "Job Not Found" });
            return;
        }

        res.status(200).json(jobDetails);
    } catch (error) {
        console.error("Error:", error.message);
        res.status(500).json({ error: "Server error" });
    }
});



//user apply for job
app.post("/jobs/:id/apply", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const jobId = req.params.id;

        const checkApplicationQuery = `SELECT * FROM job_applications WHERE user_id = ? AND job_id = ?`;
        const application = await database.get(checkApplicationQuery, [userId, jobId]);

        if (application) {
            return res.status(400).json({ error: "You have already applied for this job" });
        }

        const applyJobQuery = `INSERT INTO job_applications (user_id, job_id) VALUES (?, ?)`;
        await database.run(applyJobQuery, [userId, jobId]);

        res.status(200).json({ message: "Successfully Applied" });
    } catch (error) {
        console.error("Apply Job Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


//user can see applied jobs
app.get("/jobs/applied", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        const getAppliedJobsQuery = `
            SELECT jobs.* FROM jobs
            INNER JOIN job_applications ON jobs.id = job_applications.job_id
            WHERE job_applications.user_id = ?;
        `;

        const appliedJobs = await database.all(getAppliedJobsQuery, [userId]);

        res.status(200).json({ appliedJobs });
    } catch (error) {
        console.error("Applied Jobs Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



//recruiters update their jobs
app.put("/jobs/:id", authenticateToken, async(req, res)=> {
    try {
        if(req.user.role !== "recruiter"){
            return res.status(403).json({error: "Only recruiters can update jobs"})
        }

        const jobId = req.params.id
        const { title, companyName, location, salary, jobType, description, aboutCompany, skill } = req.body;

        const updateJobQuery = `
            UPDATE jobs 
            SET title = ?, company_name = ?, location = ?, salary = ?, job_type = ?, description = ?, about_company = ?, skill = ? 
            WHERE id = ? AND recruiter_id = ?;
        `;

        await database.run(updateJobQuery, [title, companyName, location, salary, jobType, description, aboutCompany, skill, jobId, req.user.id]);

        res.status(200).json({ message: "Job updated successfully" });

    } catch (error) {
        console.error("Update Job Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
})


//recruiters delete their jobs
app.delete("/jobs/:id", authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== "recruiter") {
            return res.status(403).json({ error: "Only recruiters can delete jobs" });
        }

        const jobId = req.params.id;

        const deleteJobQuery = `DELETE FROM jobs WHERE id = ? AND recruiter_id = ?`;
        await database.run(deleteJobQuery, [jobId, req.user.id]);

        res.status(200).json({ message: "Job deleted successfully" });
    } catch (error) {
        console.error("Delete Job Error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
