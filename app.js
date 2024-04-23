const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');






const app = express();
app.use(express.json());
app.use(bodyParser.json());


const router = require('./APP/routes/users');

dotenv.config();



app.use('/api',router)

// Parse JSON bodies
app.use(bodyParser.json());




//starting the server
app.listen(9083, ()=>{
    console.log("Server running on port 9083")
})
const MONGO_URL = process.env.MONGO_URL
//path
const PORT = process.env.PORT || 9083;

//Connect to MongoDB
mongoose.connect(process.env.MONGO_URL)
.then(() => console.log("Connected to database"))
.catch((err) => console.log(err))

//mongoose.connect("mongodb+srv://Lightest:Lightest123@cluster0.uuhjvqf.mongodb.net/lightest?retryWrites=true&w=majority&appName=Cluster0")
