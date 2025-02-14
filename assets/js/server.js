require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mysql = require('mysql');

const app = express();

// Konfigurasi session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// Koneksi ke database MySQL
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log("Database connected...");
});

// Konfigurasi Passport Google OAuth2
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;
    const googleId = profile.id;
    const name = profile.displayName;

    // Cek apakah user sudah ada di database
    db.query("SELECT * FROM users WHERE google_id = ?", [googleId], (err, result) => {
        if (err) return done(err);

        if (result.length > 0) {
            return done(null, result[0]); // User ditemukan
        } else {
            // Jika user belum ada, simpan ke database
            db.query("INSERT INTO users (username, email, google_id) VALUES (?, ?, ?)", 
            [name, email, googleId], (err, res) => {
                if (err) return done(err);
                db.query("SELECT * FROM users WHERE google_id = ?", [googleId], (err, newUser) => {
                    if (err) return done(err);
                    return done(null, newUser[0]);
                });
            });
        }
    });
}));

// Serialize & Deserialize User
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    db.query("SELECT * FROM users WHERE id = ?", [id], (err, result) => {
        if (err) return done(err);
        done(null, result[0]);
    });
});

// Rute Login Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/login'
}), (req, res) => {
    // Jika sukses login, redirect ke halaman dashboard
    res.redirect('http://localhost/your_project/dashboard.php');
});

// Rute Logout
app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/login');
    });
});

// Jalankan server di port 5000
app.listen(5000, () => {
    console.log("Server berjalan di http://localhost:5000");
});
