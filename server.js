const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || "jwt-secret-key"

const app = express();

app.use(cookieParser());

const authorization = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.sendStatus(403);
    }
    try {
        const data = jwt.verify(token, JWT_SECRET_KEY);
        req.user = data.user;
        req.role = data.role;
        return next();
    } catch (err) {
        console.log(err);
        return res.sendStatus(403);
    }
};

app.get("/", (req, res) => {
    return res.json({ message: "You have reached a running service" });
});

app.get("/login", (req, res) => {
    const user = req.query.user;
    if(user) {
        const token = jwt.sign({ user: user, role: "user" }, JWT_SECRET_KEY);
        return res
            .cookie("token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
            })
            .status(200)
            .json({ message: "Logged in successfully" });
    } else {
        return res.sendStatus(400);
    }
});

app.get("/protected", authorization, (req, res) => {
    return res.json({ user: { user: req.user, role: req.role } });
});

app.get("/logout", authorization, (req, res) => {
    return res
        .clearCookie("token")
        .status(200)
        .json({ message: "Successfully logged out" });
});

const start = (port) => {
    try {
        app.listen(port, () => {
            console.log(`Api up and running at: http://localhost:${port}`);
        });
    } catch (error) {
        console.error(error);
        process.exit();
    }
};
start(process.env.PORT || 5001);