import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../models/auth/userModel.js";

export const protect = asyncHandler(async (req, res, next) => {
  try {
    //check if user is logged in
    const token = req.cookies.token;

    if (!token) {
      res.status(401).json({ message: "not authorized, please login" });
    }
    //verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    //get user details from the token excluding the password
    const user = await User.findById(decoded.id).select("-password");
    //check if user exists
    if (!user) {
      res.status(404).json({ message: "user not found" });
    }
    //set user details in the request object
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: "not authorized,token failed" });
  }
});

//admin middleware
export const adminMiddleware = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    //if user is admin, move to the next middleware/controller
    next();
    return;
  }
  //if not admin send 403 forbidden or terminate request
  res.status(403).json({ message: "only admins can do this" });
});

//creator middleware
export const creatorMiddleware = asyncHandler(async (req, res, next) => {
  if (
    (req.user && req.user.role === "creator") ||
    (req.user && req.user.role === "admin")
  ) {
    //if user is a creator, move to the next middleware
    next();
    return;
  }
  res.status(403).json({ message: "only creators can do this" });
});

//verification middleware
export const verifiedMiddleware = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified) {
    next();
    return;
  }
  res.status(403).json({ message: "please verify your email address" });
});
