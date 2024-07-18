const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;


app.use(express.json());
app.use(cors());


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nnvexxr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();

    const database = client.db("Mobile-Wallet");
    const userCollection = database.collection("users");

    app.post('/verifyToken', async (req, res) => {
      const { token } = req.body;

      try {
        const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
        const user = await userCollection.findOne({ _id: new ObjectId(decoded.userId) });

        if (!user) {
          return res.status(400).json({ error: 'User not found' });
        }

        res.status(200).json({ user });
      } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
      }
    });

    app.post('/register', async (req, res) => {
      const { name, pin, mobileNumber, email } = req.body;

      const user = await userCollection.findOne({
        $or: [{ email: email }, { mobileNumber: mobileNumber }]
      });

      if (user) {
        return res.send({ message: "User already registered" });
      }

      const hashedPin = await bcrypt.hash(pin, 10);

      const newUser = {
        name,
        pin: hashedPin,
        mobileNumber,
        email,
        status: 'pending'
      };

      const result = await userCollection.insertOne(newUser);
      res.send(result);

    });

    app.post('/login', async (req, res) => {
      const { identifier, pin } = req.body;

      const user = await userCollection.findOne({
        $or: [{ email: identifier }, { mobileNumber: identifier }]
      });

      if (!user) {
        return res.status(400).json({ error: 'User not found' });
      }

      // Compare the provided PIN with the stored hashed PIN
      const isMatch = await bcrypt.compare(pin, user.pin);

      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid PIN' });
      }

      if (user.status === "pending") {
        return res.status(400).json({ error: 'User account is pending approval' });
      }

      const token = jwt.sign({ userId: user._id }, process.env.TOKEN_SECRET);

      res.status(200).json({ user, token });
    });


    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
  res.send('Welcome to Mobile Wallet!');
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});