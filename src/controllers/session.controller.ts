import config from "config";
import {Request, Response} from "express";
import { createSession } from "../service/session.service";
import { validatePassword } from "../service/user.service";
import { signJwt } from "../utils/jwt.utils";


export async function createUserSessionHandler(req: Request, res:Response){
    /* Validate the user's password**/
    
    const user = await validatePassword(req.body)
    if(!user){
        return res.status(401).send("Invalid email or password");
    }
    //Create a session for the user
    const session = await createSession(user._id, req.get("user-agent") || "")

    //Create access token for user
    const accessToken = signJwt({
        ...user, session: session._id}, 
        {expiresIn: config.get("accessTokenTimeToLive")} //15 minutes
        
    )

    //create refresh token
    const refreshToken = signJwt({
        ...user, session: session._id}, 
        {expiresIn: config.get("refreshTokenTimeToLive")} //1 year   
    )

    // return acces and refresh tokens

    return res.send({accessToken, refreshToken})
}

    