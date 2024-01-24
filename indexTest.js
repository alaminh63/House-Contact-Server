process.noDeprecation = true;
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config(); // Load environment variables from a .env file

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// MongoDB Server Connect
const uri = `mongodb+srv://${process.env.USER_NAME}:${process.env.SECRET_PASSWORD}@cluster0.pdzlhd7.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const authenticateUser = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized access" });
  }

  const token = authorization.split(" ")[1];
  jwt.verify(token, process.env.SECRET_KEY, (error, decoded) => {
    if (error) {
      return res
        .status(401)
        .send({ error: true, message: "Unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

async function run() {
  try {
    await client.connect();
    const usersCollection = client.db("houseHunter").collection("users");

    app.post("/register", async (req, res) => {
      try {
        const userData = req.body;
        const { name, email, password, photo_url } = userData;

        if (!name || !email || !password || !photo_url) {
          return res
            .status(400)
            .send({ error: true, message: "All fields are required" });
        }

        const existingUser = await usersCollection.findOne({ email: email });
        if (existingUser) {
          return res
            .status(400)
            .send({ error: true, message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
          name,
          email,
          password: hashedPassword,
          photo_url,
          role: "role",
        };

        const result = await usersCollection.insertOne(newUser);

        if (result && result.ops && result.ops.length > 0) {
          res.status(201).send(result.ops[0]);
        } else {
          console.error(
            "Error registering user: Unable to retrieve inserted user"
          );
          res
            .status(500)
            .send({ error: true, message: "Internal server error" });
        }
      } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).send({ error: true, message: "Internal server error" });
      }
    });

    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({ email: email });
        if (!user) {
          return res
            .status(401)
            .send({ error: true, message: "Invalid credentials" });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
          return res
            .status(401)
            .send({ error: true, message: "Invalid credentials" });
        }

        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.SECRET_KEY
        );
        res.send({ token });
      } catch (error) {
        console.error("Error during login:", error);
        res.status(500).send({ error: true, message: "Internal server error" });
      }
    });

    app.get("/user", authenticateUser, async (req, res) => {
      try {
        const decodedEmail = req.decoded.email;

        const user = await usersCollection.findOne({ email: decodedEmail });

        if (!user) {
          return res
            .status(404)
            .send({ error: true, message: "User not found" });
        }

        const { name, email, photo_url, role } = user;
        res.send({ name, email, photo_url, role });
      } catch (error) {
        console.error("Error fetching user data:", error);
        res.status(500).send({ error: true, message: "Internal server error" });
      }
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    app.get("/", (req, res) => {
      res.send("Server is running");
    });

    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
  }
}

run().catch(console.dir);
