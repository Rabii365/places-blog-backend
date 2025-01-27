const express = require("express");
const { getUsers, signup, login } = require("../controllers/users-controller");
const { check } = require("express-validator");
const fileUpload = require("../middleware/file-upload");

const router = express.Router();

router.get("/", getUsers);

router.post(
  "/signup",
  fileUpload.single("image"),
  [
    check("name").not().isEmpty(),
    check("email").normalizeEmail().isEmail(),
    check("password").isLength({ min: 6 }),
  ],
  signup
);

router.post("/login", login);

module.exports = router;
