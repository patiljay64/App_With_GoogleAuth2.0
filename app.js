
//-------------------------require---------------------------------

require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");


//-------------------------app set---------------------------------
const app = express();
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");


//-------------------------Session---------------------------------

app.use(session({
    secret: "This is a secret string",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


//-------------------------Database---------------------------------

//connection
mongoose.connect(process.env.MONGO_CONNECTION)  
    .then(() => {
        console.log("Connected Successfully");
    })
    .catch((err) => {
        console.log(err);
    });

// Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

//-------------------------Google Auth---------------------------------
passport.use(new GoogleStrategy({

    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

//-------------------------GOOGLE Authanticate Page---------------------------------
app.get("/auth/google", passport.authenticate("google", {

    scope: ["profile"]

}));

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });


//-------------------------Home Route---------------------------------

app.get("/", (req, res) => {
    res.render("home");
});


//-------------------------Register Route---------------------------------

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register", (req, res) => {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });

});


//-------------------------Login Route---------------------------------

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});


//-------------------------Secret Route---------------------------------

app.get("/secrets", (req, res) => {
    User.find({ "secret": { $ne: null } })
        .then((foundUsers) => {
            if (foundUsers) {
                res.render("secrets", {
                    userWithSecrets: foundUsers
                })
            }
        })
});


//-------------------------Submit Route---------------------------------

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.redirect("/login");
    }
});


app.post("/submit", (req, res) => {

    User.findById(req.user)
        .then((foundUser) => {
            if (foundUser) {
                foundUser.secret = req.body.secret;
                foundUser.save()
                    .then(() => {
                        console.log("Secret Submitted");
                        res.redirect("/secrets");
                    })
                    .catch((err) => {
                        console.log(err);
                    });
            }
        })
        .catch(err => {
            console.log(err);
        });
});


//-------------------------logout Route---------------------------------

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
});


//-------------------------Server---------------------------------

app.listen(3000, () => {
    console.log("server is up at the port 3000");
});

