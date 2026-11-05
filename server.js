const express = require("express");               // imports the express module
const crypt = require("crypto");                  // built in module used to scramble passwords
const app = express();                            // creates the express application object
const session = require("express-session");       // lets the server remember a logged in user
const cookieParser = require("cookie-parser");    // reads the cookie that holds the session id

app.use(express.urlencoded({ extended: true }));  // lets express read data sent from a form
app.use(express.static("public"));                // serves the html files out of the public folder
app.use(cookieParser());                          // turns on the cookie reader

// sets up the sessions, which is how the site remembers who is logged in
app.use(session({
	secret: process.env.SESSION_SECRET,           // signs the session id cookie
	resave: false,                                // does not resave a session that has not changed
	saveUninitialized: false,                     // does not store empty sessions
	cookie: {
		maxAge: 60000 * 60,                       // the session lasts one hour
		httpOnly: true,                           // javascript in the browser cannot read the cookie
		secure: false                             // would be true if the site used https
	}
}));

const mysql = require("mysql2");                  // the mysql2 database driver
const pass = process.env.ROOTPASS;                // reads the password from an environment variable
const conn = mysql.createConnection(              // the details node uses to reach mysql
{host:"localhost", user:"root", password:pass, database:"movietracker", port:3306});

// settings used whenever a password is hashed
const hashRounds = 100;                           // how many times the hash is repeated
const hashLength = 64;                            // how many bytes long the hash should be
const salt = "salt";                              // extra text mixed into every password

conn.connect(function(err)                        // opens the connection to the database
{
	if(err)
		console.log("Couldnt connect to MySQL", err);   // prints the reason it failed
	else
		console.log("Database connection established"); // prints on success
});


// runs when the register form is submitted
app.post("/register", function(req, res)
{
	let username = req.body.username;             // the username typed into the form
	let email = req.body.email;                   // the email typed into the form
	let plainPass = req.body.password;            // the password typed into the form

	// scramble the password so the real one is never stored in the database
	let hashedPass = crypt.pbkdf2Sync(plainPass, salt, hashRounds, hashLength, 'sha512').toString('hex');

	// the question marks get filled in by the values in the array below
	let sql = "insert into users (username, email, password) values (?,?,?)";

	conn.query(sql, [username, email, hashedPass], function(err, result)
	{
		if (err)                                  // usually means the username or email is taken
			res.send('<p>There was an error registering you<br><a href="register.html">Try again</a> here</p>');
		else
			res.send('<p>You have successfully registered, ' + username + '<br><a href="login.html">Login</a> here</p>');
	});
});


// runs when the login form is submitted
app.post("/login", function(req, res)
{
	let username = req.body.username;             // the username typed into the form
	let plainPass = req.body.password;            // the password typed into the form

	// hash it the same way as before so it can be compared with the stored one
	let hashedPass = crypt.pbkdf2Sync(plainPass, salt, hashRounds, hashLength, 'sha512').toString('hex');

	// look for a row where the username and the hashed password both match
	let sql = "select * from users where username=? and password=?";

	conn.query(sql, [username, hashedPass], function(err, result)
	{
		if(err)
			res.send(err);
		else
		{
			if (result.length === 0)              // nothing matched, so the details were wrong
				res.send('<p>The login credentials were incorrect<br><a href="login.html">Login</a> here</p>');
			else                                  // a row came back, so the login worked
			{
				// save the user in the session so the other pages know who is logged in
				req.session.user = {username:result[0].username, email:result[0].email};

				res.send('<p>You have logged in successfully, ' + username + '.<br>Visit your <a href="/profile">Profile</a></p>');
			}
		}
	});
});


// shows the logged in user their own details
app.get("/profile", function(req, res)
{
	if (!req.session.user)                        // nothing in the session means nobody is logged in
		res.send('<p>You are not logged in. Please <a href="login.html">Login</a> here</p>');
	else
	{
		// the username comes out of the session, not out of the form or the database
		res.send('<p>Hi ' + req.session.user.username + '. Your email is ' + req.session.user.email +
		         '.<br><a href="/logout">Logout</a></p>');
	}
});


// throws the session away so the user is logged out
app.get("/logout", function(req, res)
{
	req.session.destroy(function(err)             // deletes everything stored in the session
	{
		if (err)
			res.send("Error logging out");
		else
			res.send('<p>Logged out successfully! <a href="login.html">Login</a> here</p>');
	});
});


app.listen(3000);                                 // starts the server on port 3000
