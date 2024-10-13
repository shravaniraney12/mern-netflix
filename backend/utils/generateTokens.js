import jwt from "jsonwebtoken";
import { ENV_VARS } from "../config/envVars.js";

export function generateTokenAndSetCookie(userId, res){
  const token = jwt.sign({userId}, ENV_VARS.JWT_SECRET, {expiresIn:"7d"});
  res.cookie("jwt-netflix", token, {
    maxAge: 7*24*60*60*1000,
    httpOnly:true, //prvents cookie from being accessed by client side js
    sameSite: "strict",
    secure: ENV_VARS.NODE_ENV !== "development",
  });
  return token;
}