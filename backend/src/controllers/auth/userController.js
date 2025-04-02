import asyncHandler from "express-async-handler";
import User from "../../models/auth/userModel.js";
import generateToken from "../../helpers/generateToken.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Token from "../../models/auth/Token.js";
import crypto from "node:crypto";
import hashToken from "../../helpers/hashedToken.js";
import sendEmail from "../../helpers/sendEmail.js";

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

//login status
export const userLoginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    res.status(401).json({ message: "not authorized, please login!" });
  }
  //verify the token
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  if (decoded) {
    res.status(200).json(true);
  } else {
    res.status(401).json(false);
  }
});

//email verification
export const verifyEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  //check if user exists
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  //check if user is verified
  if (user.isVerified) {
    return res.status(400).json({ message: "User is already verified" });
  }

  //if user is not verified
  const token = await Token.findOne({ userId: user._id });
  //if token exists delete the token
  if (token) {
    await token.deleteOne();
  }
  //create a verification token using the user id -> crypto module
  const verificationToken = crypto.randomBytes(64).toString("hex") + user._id;

  //hash the verification token
  const hashedToken = await hashToken(verificationToken);

  await new Token({
    userId: user._id,
    verificationToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, //24 hours
  }).save();

  //verification link
  const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
  //send email
  const subject = "Email verification - Authkit";
  const send_to = user.email;
  const reply_to = "noreply@gmail.com";
  const template = "emailVerification";
  const send_from = process.env.USER_EMAIL;
  const name = user.name;
  const link = verificationLink;

  try {
    await sendEmail(
      subject,
      send_to,
      send_from,
      reply_to,
      template,
      name,
      link
    );
    return res.status(200).json({ message: "email sent" });
  } catch (error) {
    console.log("Error sending email: ", error);
    return res.status(500).json({ message: "Email could not be sent" });
  }
});

//verify user
export const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  if (!verificationToken) {
    res.status(400).json({ message: "inavlid verification token" });
  }
  //hash verification token because it was hashed before saving
  const hashedToken = hashToken(verificationToken);
  //find user with verification token
  const userToken = await Token.findOne({
    verificationToken: hashedToken,
    //check if token is not expired
    expiresAt: { $gt: Date.now() },
  });
  // res.status(200).json({ message: "otp verified successfully" });
  if (!userToken) {
    return res
      .status(400)
      .json({ message: "invalid or expired verification token" });
  }
  //find user with the user id in the token
  const user = await User.findById(userToken.userId);
  //if user is already verified
  if (user.isVerified) {
    return res.status(400).json({ message: "user already verified" });
  }
  //update the user to verified
  user.isVerified = true;
  await user.save();
  res.status(200).json({ message: "user verified" });
});

//forgot password
export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  //check if email exists
  if (!email) {
    return res.status(400).json({ message: "email is required" });
  }
  //check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(400).json({ message: "user not found" });
  }
  //see if reset token exists
  let token = await Token.findOne({ userId: user._id });

  //if token exists then delete the token
  if (token) {
    await token.deleteOne();
  }
  //create a reset token using the user id and expires in 1 hour
  const passwordResetToken = crypto.randomBytes(64).toString("hex") + user._id;
  //hash the token
  const hashedToken = hashToken(passwordResetToken);
  await new Token({
    userId: user._id,
    passwordResetToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * 60 * 1000, //1 hour
  }).save();

  //create the reset link
  const resetLink = `${process.env.CLIENT_URL}/reset-password/${passwordResetToken}`;

  //send email to user
  const subject = "Password reset - Authkit";
  const send_to = user.email;
  const send_from = process.env.USER_EMAIL;
  const reply_to = "noreply@noreply.com";
  const template = "forgotPassword";
  const name = user.name;
  const url = resetLink;

  try {
    await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
    res.json({ message: "email sent" });
  } catch (error) {
    console.log("error sending email :", error);
    return res.status(500).json({ message: "email could not be sent" });
  }
});

//reset password
export const resetPassword = asyncHandler(async (req, res) => {
  const { resetPasswordToken } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ message: "password is required" });
  }

  //hash the reset token
  const hashedToken = hashToken(resetPasswordToken);
  //check if token exists and has not expired
  const userToken = await Token.findOne({
    passwordResetToken: hashedToken,
    //check if the token has expired
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    return res.status(400).json({ message: "invalid or expired reset token" });
  }
  //find user with the user id in the token
  const user = await User.findById(userToken.userId);

  //update the user password
  user.password = password;
  await user.save();

  res.status(200).json({ message: "password reset successfully" });
});

//update password
export const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: "All fields are required!" });
  }
  //find user by id
  const user = await User.findById(req.user._id);

  //compare if current password matches the one in the datatbase
  const isMatch = await bcrypt.compare(currentPassword, user.password);

  if (!isMatch) {
    return res.status(400).json({ message: "invalid password!" });
  }

  //reset password
  if (isMatch) {
    user.password = newPassword;
    await user.save();
    return res.status(200).json({ message: "password Changed successfully" });
  } else {
    return res.status(400).json({ message: "password could not be changed" });
  }
});
