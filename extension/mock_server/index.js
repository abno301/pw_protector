const express = require("express");
const app = express();
const port = 9000;
const cors = require("cors");

app.use(cors());

const user = {
  username: "useraaaa",
  email: "jaka@example.com",
  password: "geslo123",
};

app.get("/user", (req, res) => {
  res.json(user);
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
