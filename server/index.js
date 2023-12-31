require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const router = require("./router/index");
const errorMiddlware = require("./middlewares/error-middlware");


const PORT = process.env.PORT || 5000;
const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true, origin: process.env.CLIENT_URL }));
app.use("/api", router);
app.use(errorMiddlware);

const start = async () => {
   await mongoose.connect(process.env.DB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true
   })
   try {
      app.listen(PORT, () => {
         console.log(`Server started on port ${PORT}`)

      })
   } catch (error) {
      console.log(error)
   }

};

start();

