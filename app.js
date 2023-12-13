"use strict";

require("dotenv").config();
const mongoose = require("mongoose");
const ExpressAdapter = require("./adapters/ExpressAdapter");
const AuthInteractor = require("./useCases/AuthInteractor");
const UserInteractor = require("./useCases/UserInteractor");

const MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_USER_PASSWORD}@${process.env.CLUSTER}.${process.env.DB_CLOUD_URL}/${process.env.DB}?retryWrites=true&w=majority`;

try {
  mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
} catch (error) {
  console.log("ERROR Connecting to mongo db: ", error);
}

const userInteractor = new UserInteractor();
const authInteractor = new AuthInteractor();

const expressAdapter = new ExpressAdapter(userInteractor, authInteractor);

const express = require("express");
const app = express();

expressAdapter.initConfigs(app);

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
