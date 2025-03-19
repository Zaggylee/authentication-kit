import asyncHandler from "express-async-handler";
import User from "../../models/auth/userModel.js";
import generateToken from "../../helpers/generateToken.js";
import bcrypt from "bcrypt";

export const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //validation
  if (!name || !email || !password) {
    //400 badd request
    res.status(400).json({ message: "all fields are required" });
  }
  //to check password length
  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: "password must be atleast 6 characters" });
  }

  //to check if user already exists in the database
  const userExists = await User.findOne({ email });

  if (userExists) {
    return res.status(400).json({ message: "user already exists" });
  }
  //create new user
  const user = await User.create({
    name,
    email,
    password,
  });
  //generate token with user id
  const token = generateToken(user._id);
  //send back the user data and token in the response to the client
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000, //30 days
    sameSite: true,
    secure: true,
  });
  if (user) {
    const { _id, name, email, role, photo, bio, isVerified } = user;
    //created
    res.status(201).json({
      _id,
      name,
      email,
      role,
      photo,
      bio,
      isVerified,
      token,
    });
  } else {
    res.status(400).json({ message: "invalid user data" });
  }
});

//user login
export const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "all fields are required" });
  }
  //check if user exists
  const userExists = await User.findOne({ email });
  if (!userExists) {
    return res.status(400).json({ message: "User not found, sign up" });
  }
  //check if the password matches hashed password in the database
  const isMatch = await bcrypt.compare(password, userExists.password);
  if (!isMatch) {
    return res.status(400).json({ message: "invalid credentials" });
  }
  //generate token with user id
  const token = generateToken(userExists._id);
  if (userExists && isMatch) {
    const { _id, name, email, role, bio, photo, isVerified } = userExists;
    //set the token in the cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: true,
      secure: true,
    });
    //send back the user and token in the response to the client
    res.status(201).json({
      _id,
      name,
      email,
      role,
      photo,
      bio,
      isVerified,
      token,
    });
  } else {
    res.status(400).json({ message: "invalid email or password" });
  }
});

//logout user
export const logoutUser = asyncHandler(async (req, res) => {
  res.clearCookie("token");

  res.status(200).json({ message: "user logged out" });
});

//get user
export const getUser = asyncHandler(async (req, res) => {
  //get user details from the token excluding the password
  const user = await User.findById(req.user._id).select("-password");

  if (user) {
    res.status(200).json(user);
  } else {
    res.status(404).json({ message: "user not found" });
  }
});

//update user
export const updateUser = asyncHandler(async (req, res) => {
  //get user details from the token coming from the protect middleware
  const user = await User.findById(req.user._id);
  if (user) {
    //user properties to update
    const { name, bio, photo } = req.body;
    //update user properties
    user.name = req.body.name || user.name;
    user.bio = req.body.bio || user.bio;
    user.photo = req.body.photo || user.photo;

    //save the updates
    const updated = await user.save();

    res.status(200).json({
      _id: updated._id,
      name: updated.name,
      email: updated.email,
      role: updated.role,
      photo: updated.photo,
      bio: updated.bio,
      isVerified: updated.isVerified,
    });
  } else {
    res.status(404).json({ message: "User not found" });
  }
});
