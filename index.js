require("./utils.js");

require('dotenv').config();
const express = require('express');

const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;


const port = process.env.PORT || 8080;

const app = express();

const Joi = require("joi");


const expireTime = 60 * 60 * 1000; 

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false, 
    resave: true
}
));

app.get('/', (req, res) => {
    var email = req.session.email;

    if (!email) {
        res.render('home', {email: null, name: null});
    } else {
        res.render('home', {email: email, name: req.session.name});
    }
});


app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.render('nosql-injection', {userProvided: false, username: null});
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('nosql-injection', {userProvided: true, username: null, validationError: true});
        return;
    }

    const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

    console.log(result);

    res.render('nosql-injection', {userProvided: true, username: username});
});


app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    res.render('contact', {missingEmail:missingEmail});
});


app.get('/admin', async (req, res) => {
    var email = req.session.email;

    if (!email) {
        res.redirect('/login');
        return;
    }

    const result = await userCollection.findOne({ email: email });
if (result.user_type !== "admin") {
    res.render('forbidden');
    return;
}


const users = await userCollection.find().project({ _id: 1, name: 1, email: 1, user_type: 1 }).toArray();
   
    res.render('admin', { users: users });
});

app.get('/members', (req, res) => {
	if (req.session.email) {
    	res.render('cow', {
			session: req.session,
			id: Math.random() * 3 + 1});
	} else {res.redirect('/');}
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/contact?missing=1');
    }
    else {
        res.render('submitEmail',{email: email});
    }
});

app.get('/signup', (req,res) => {

    res.render('signup');
});

app.get('/login', (req,res) => {
    var email = req.session.email;
    if (email) {
        res.redirect('/');
    }
    res.render('login');
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().min(1).max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect(`/signupSubmit?error=${encodeURIComponent(validationResult.error.details[0].message)}`);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user" });

    console.log('Inserted user');

    // Create a session for the new user
    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = name;
    req.session.password = hashedPassword;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});


app.get('/signupSubmit', (req, res) => {
    const errorMessage = decodeURIComponent(req.query.error);
    res.render('signupSubmit',{errorMessage: errorMessage});
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/login');
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log('user not found');
        res.redirect(`/loginSubmit?error=User not found`);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log('correct password');
        req.session.authenticated = true;
        req.session.email = email;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    } else {
                console.log('incorrect password');
        res.redirect(`/loginSubmit?error=Password is incorrect`);
        return;
    }
});

app.get('/loginSubmit', (req, res) => {
    const errorMessage = req.query.error;
    res.render('loginSubmit',{errorMessage:errorMessage});
});

app.get('/loggedin', (req,res) => {

    if (!req.session.authenticated) {
        res.redirect('/login');
    } else {
        res.redirect('/members');
    }
});

app.get('/signout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log("Error destroying session:", err);
        } else {
            console.log("Session destroyed successfully");
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});


app.get('/cow/:id', (req, res) => {
    var cowId = req.params.id;
    var isValidCow = cowId == 1 || cowId == 2 || cowId == 3;

    res.render('cow', { cowId: cowId, isValidCow: isValidCow });
});
app.get('/promote/:id', async (req, res) => {
    const userId = req.params.id;
    await userCollection.updateOne({ _id: new require('mongodb').ObjectID(userId) }, { $set: { user_type: "admin" } });
    res.redirect('/admin');
});

app.get('/demote/:id', async (req, res) => {
    const userId = req.params.id;
    await userCollection.updateOne({ _id: new require('mongodb').ObjectID(userId) }, { $set: { user_type: "user" } });
    res.redirect('/admin');
});


app.use(express.static(__dirname + "/public"));

app.get("/notfound", (req,res) => {
    res.status(404);
    res.render('notfound');
});

app.get("*", (req,res) => {
    res.redirect("/notfound");
});

app.listen(port, () => {
    console.log("Node application listening on port "+port);
});
