import express from "express";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const salt = 10;

const app = express();

app.use(express.json());
app.use(cors(
    {
        origin: "http://localhost:3000",
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
    }
));
app.use(cookieParser());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "T2000!@#m11p24",
    database: "ekoplasco"
});

app.post("/register", (req, res) => {
    const sql = "INSERT INTO users(username, email, password) VALUES (?, ?, ?)";

   bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
       if (err) {
           return res.json({error: "Error for hashing"});
       }
       const value = [
        req.body.username, 
        req.body.email,
        hash
    ];
    db.query(sql, value, (err, result) => {
        if (err) {
            return res.json({err : "Error for inserting"});
        }
        return res.json({status: "Successfully inserted"});
    })
   })
    
})

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({error: "Please login"});
    } else {
        jwt.verify(token, "secretkey", (err, decoded) => {
            if (err) {
                return res.json({error: "token is not okay"});
            } else {
                req.username = decoded.username;
                next();
            }
        })
    }
}

app.get("/", verifyUser, (req, res) => {
    return res.json({status: "success", username: req.username})
})

app.post("/login", (req, res) => {
    const sql = "SELECT * FROM users WHERE username = ?";
    db.query(sql, [req.body.username], (err, data) => {
        if (err) {
            return res.json({error: "Error for fetching"});
        }
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) {
                    return res.json({error: "password comparison error"});
                }
                if (response) {
                    const token = jwt.sign({username: data[0].username}, "secretkey", {expiresIn: "1h"});
                    res.cookie("token", token)
                    return res.json({status: "Successfully logged in"});
                } else {
                    return res.json({error: "Wrong password"});
                }
            })
        } else {
            return res.json({error: "User not found"});
        }
    })
})


app.post("/customer_order", (req, res) => {
    const sql = "INSERT INTO `order` (user_id, total_amount, status) VALUES (?, ?, ?)";

    const value = [
        req.body.user_id,
        req.body.total_amount,
        req.body.status
    ];

    db.query(sql, value, (err, result) => {
        if (err) {
            return res.json(err);
        }
        return res.json({status: "Successfully inserted"});
    });
});

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    return res.json({status: "Successfully logged out"});
})

app.get("/read", (req, res) => {
    const sql = "SELECT * FROM `order`";
    db.query(sql, (err, result) => {
        if (err) {
            return res.json(err);
        } else {
            return res.json(result);
        }
    })
})

app.listen(3001, () => {
    console.log("Server started on port 3001");
})