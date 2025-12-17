const express = require("express");
const cors = require("cors");
require("dotenv").config();

const auth = require("./auth");

const app = express();
app.use(cors());
app.use(express.json());

app.post("/api/auth/signup", auth.signup);
app.post("/api/auth/login", auth.login);
app.post("/api/auth/google", auth.googleLogin);


app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

app.listen(5000, () => {
  console.log("Backend running on http://localhost:5000");
});
