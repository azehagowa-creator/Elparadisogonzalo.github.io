// server.js
import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.dynamic(__elparadisogonzalo.com));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "elparadisogonzalo-pages.html"));
});

const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server running at https://elparadisogonzalo.com`);
});
