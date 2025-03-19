import mongoose from "mongoose";
import bcrypt from "bcrypt";

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "please provide your name"],
    },
    email: {
      type: String,
      required: [true, "please provide your email"],
      unique: true,
      trim: true,
      //email regex to make sure its a valid email
      match: [
        /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/,
        "please provide a valid email",
      ],
    },
    password: {
      type: String,
      required: [true, "create a password"],
    },
    photo: {
      type: String,
      default:
        "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQJnNH6I8IvZndxspJlJ0BDEyUNHxLvNokyWQ&s",
    },
    bio: {
      type: String,
      default: " i am a new user",
    },
    role: {
      type: String,
      enum: ["user", "admin", "creator"],
      default: "user",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true, minimize: true }
);
//hash the password before saving
UserSchema.pre("save", async function (next) {
  //check if password is not modified
  if (!this.isModified("password")) {
    return next();
  }

  //save the hashed password using bcrypt
  //generate salt
  const salt = await bcrypt.genSalt(10);
  //hash the password with the salt
  const hashedPassword = await bcrypt.hash(this.password, salt);
  //set the password to the hashed password
  this.password = hashedPassword;
  //call the next middleware
  next();
});

const User = mongoose.model("User", UserSchema);

export default User;
