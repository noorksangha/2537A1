
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
        res.send(`
        <form action='/signup' method='get'><button>Sign Up</button><br></form>
        <form action='/login' method='get'><button>Log in</button></form>
        `);
    } else {
        var string = `<h2>Hello, ` + req.session.name + `!</h2>`;
        var members = `<form action='/members' method='get'><button>Go to Members Area ;)</button></form>`;
        var signout = `<form action='/signout' method='get'><button>Sign Out</button></form>`;
        var html = string + members + signout;
        res.send(html);
    }
});



app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.get('/members', (req, res) => {
    var email = req.session.email;

    if (!email) {
        res.redirect('/login');
    }
    var msg = "<h3>Hello, " + req.session.name + "! Enjoy these cute pictures of mini cows :)</h3>";
    var signout = "<form action='/signout' method='get'><button>Sign Out</button><br></form>";
    var id = Math.floor(Math.random() * 3) + 1;
    var img = "<img src='/" + id + ".png'>";
    var html = msg + `<br>` + img + signout;
    res.send(html);
});



app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'><br>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var email = req.session.email;
    if (email) {
        res.redirect('/');
    }
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
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
    var html = `
    <p>${errorMessage}. <a href='/signup'>Try again</a></p>
    `;
    res.send(html);
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
    var html = `
    <p>${errorMessage}. <a href='/login'>Try again</a></p>
    `;
    res.send(html);
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



app.get('/cow/:id', (req,res) => {

    var cow = req.params.id;

    if (cow == 1) {
        res.send("cow 1: <img src='/1.png' style='width:250px;'>");
    }
    else if (cow == 2) {
        res.send("cow 2: <img src='/2.png' style='width:250px;'>");
    }
    else if (cow == 3) {
        res.send("cow 3: <img src='/3.png' style='width:250px;'>");
    }
    else {
        res.send("Invalid cow id: "+ cow);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("/notfound", (req,res) => {
    res.status(404);
    res.send("Page not found - 404");

});

app.get("*", (req,res) => {
    res.redirect("/notfound");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
