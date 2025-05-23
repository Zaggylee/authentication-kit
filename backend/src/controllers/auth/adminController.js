import asyncHandler from "express-async-handler";
import User from "../../models/auth/userModel.js";

export const deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.params;
  //atempt to find and delete the user
  try {
    const user = await User.findByIdAndDelete(id);
    //check if user exists
    if (!user) {
      res.status(404).json({ message: "user not found" });
    }
    //if user is found then delete user
    res.status(200).json({ message: "user deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "cannot delete user" });
  }
});

//get all users
export const getAllUsers = asyncHandler(async (req, res) => {
  try {
    const users = await User.find({});
    if (!users) {
      res.status(404).json({ message: "no users found" });
    }
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: "Cannot get users" });
  }
});
