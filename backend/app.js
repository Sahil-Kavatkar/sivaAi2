if (process.env.NODE_ENV != "production") {
    require('dotenv').config();
}

const express = require("express");
const app = express();

const mongoose = require("mongoose");
const User = require("./models/user.js");
const Admin = require('./models/admin.js');
const ejs = require('ejs');
const path = require("path");
const ejsMate = require("ejs-mate");
// const wrapAsync = require("./utils/wrapAsync.js");
const ExpressError = require("./utils/ExpressError.js");
const bodyParser = require('body-parser')
const multer = require("multer");
const xlsx = require("xlsx");

const session = require('express-session')
const passport = require('passport');
const MongoStore = require('connect-mongo');

const LocalStrategy = require('passport-local');
const GoogleStrategy = require('passport-google-oauth2').Strategy;


const nodemailer = require('nodemailer');
const otp = require('otplib');

const DOMPurify = require('dompurify'); 
const { JSDOM } = require('jsdom');    
const window = new JSDOM('').window;   // Create a window object for DOMPurify
const purify = DOMPurify(window);      
const QRCode = require("qrcode");

const __dirname = path.resolve();

const crypto = require('crypto'); // For generating random reset tokens
const cors = require('cors');
app.use(cors({
  origin: 'https://siva-ai-2.onrender.com', 
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  credentials: true 
}));


// const { Vonage } = require('@vonage/server-sdk')



const MONGO_URL = process.env.ATLASDB_URL;
// const FRIEND_MONGO_URL = "mongodb+srv://dhruvpatel150204:internship123@cluster0.ec2du.mongodb.net/SIH?retryWrites=true&w=majority&appName=Cluster0";

// async function connectToDatabases() {
//     try {
//         // Connect to your primary database
//         await mongoose.connect(MONGO_URL);
//         console.log("Connected to your primary database");

//         // Create a separate connection for your friend's database
//         const friendConnection = await mongoose.createConnection(FRIEND_MONGO_URL).asPromise();
//         console.log("Connected to friend's database");

//         const genericSchema = new mongoose.Schema({}, { strict: false });
//         const FriendModel = friendConnection.model('FriendData', genericSchema, 'analytics');
        
//         const friendData = await FriendModel.find({});
        

//         // More detailed investigation
//         const collection = friendConnection.db.collection('analytics');
        
//         // Get total document count directly
//         const documentCount = await collection.countDocuments();
//         console.log("Total document count:", documentCount);

//         // Try retrieving documents without any filter
//         const rawDocuments = await collection.find({}).toArray();
//         console.log("Raw documents count:", rawDocuments.length);
        
//         // If no documents found, try different approaches
//         if (rawDocuments.length === 0) {
//             // Check for any potential filtering issues
//             console.log("Trying to find with different methods:");
            
//             // Try with different query methods
//             const findResult = await FriendModel.find().lean();
//             console.log("Mongoose .find() result:", findResult.length);

//             const directMongoFind = await collection.find({}).limit(10).toArray();
//             console.log("Direct MongoDB find result:", directMongoFind.length);
            
//             if (directMongoFind.length > 0) {
//                 console.log("Sample document:", directMongoFind[0]);
//             }
//         }

//         return {
//             primaryConnection: mongoose.connection,
//             friendConnection: friendConnection
//         };
//     } catch (error) {
//         console.error("Detailed connection error:", error);
//         throw error;
//     }
// }

// // Call the function to connect
// connectToDatabases()
//     .then(() => {
//         console.log("Databases connected successfully");
//     })
//     .catch((err) => {
//         console.error("Failed to connect to databases:", err);
//     });
// const dbUrl = process.env.ATLASDB_URL;

main().then(() => {
    console.log("connected to db");
}).catch((err) => {
    console.log(err);
});

async function main() {
    await mongoose.connect(MONGO_URL);
};




app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(bodyParser.json())
app.use(cookieParser());


const store= MongoStore.create({
    mongoUrl: MONGO_URL,
    crypto:{
        secret: 'vcet',
    },
    touchAfter:24 * 3600,
});

console.log('MongoStore initialized successfully');

store.on('create', (sessionId) => {
    console.log('Session created with ID1:', sessionId);
  });

store.on('touch', (sessionId) => {
    console.log('Session updated for ID:', sessionId);
  });

store.on("error", (err) => {
    console.log("ERROR in MongoStore:", err);
});

app.use(session({
    store,
    secret: 'vcet',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        expires: Date.now() + 7 * 24 * 60 * 60 * 1000,
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'None',
    }
    
}));


app.use(passport.initialize());
app.use(passport.session());

passport.use('user-local', new LocalStrategy({ usernameField: 'email' }, User.authenticate()));
passport.use('admin-local', new LocalStrategy({ usernameField: 'email' }, Admin.authenticate()));


passport.serializeUser((entity, done) => {
        const entityType = entity instanceof Admin ? 'Admin' : 'User';
        done(null, { id: entity.id, type: entityType });
});
    
passport.deserializeUser(async (obj, done) => {
        try {
            if (obj.type === 'Admin') {
                const admin = await Admin.findById(obj.id);
                return done(null, admin);
            } else {
                const user = await User.findById(obj.id);
                return done(null, user);
            }
        } catch (err) {
            done(err, null);
        }
});

if (process.env.NODE_ENV === "production") {
	app.use(express.static(path.join(__dirname, "/frontend/dist")));

	app.get("*", (req, res) => {
		res.sendFile(path.resolve(__dirname, "frontend", "dist", "index.html"));
	});
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'sivachatbot@gmail.com',
      pass: 'zyullbomcvdmailh'
    }
  });
  
  // Function to send OTP
  const sendOTP = async (useremail, otpCode) => {
    try {
      await transporter.sendMail({
        from: 'sivachatbot@gmail.com',
        to: useremail,
        subject: 'Your OTP Code',
        text: `Your OTP code is: ${otpCode}`,
      });
      console.log('OTP sent successfully');
    } catch (error) {
      console.error('Error sending OTP:', error);
    }
  };
  

  
  
app.get('/test-session', (req, res) => {
    if (!req.session) {
        return res.status(500).send('Session is not initialized.');
    }
    req.session.testKey = 'testValue'; // Set a test value in the session
    res.send('Session is working. Cookie should be set.');
});

app.post('/signin', async (req, res) => {
    try {
        // Sanitize user inputs
        const email = purify.sanitize(req.body.email);
        const password = purify.sanitize(req.body.password);
        const displayName = purify.sanitize(req.body.displayName);
        const organizationId = purify.sanitize(req.body.organizationId);

        console.log(email);

        const admin = await Admin.findOne({ organizationId });
        if (!admin) {
            return res.status(400).json({ error: "Invalid organization ID." });
        }

        if (!admin.approvedEmails.includes(email)) {
            return res.status(400).json({ error: "Email not approved for this organization." });
        }
        const token = crypto.randomBytes(32).toString('hex');
        const user = new User({ email, displayName, organizationId,token});
        const registeredUser = await User.register(user, password); // Automatically hashes password

        console.log("User successfully registered:", registeredUser);

        // Respond with success
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(400).json({ error: "Registration failed. Please try again." });
    }
});

app.post('/adminsignin', async (req, res) => {
    try {
        // Sanitize user inputs
        const email = purify.sanitize(req.body.email);
        const password = purify.sanitize(req.body.password);
        const displayName = purify.sanitize(req.body.name); // Map `name` to `displayName`
        const organizationId = purify.sanitize(req.body.organizationId);

        console.log('Received email:', email);
        console.log('Received displayName:', displayName);
        console.log('Received organizationId:', organizationId);

        // Create a new Admin instance
        const user = new Admin({
            email,
            displayName,
            organizationId,
        });

        // Register the user with hashed password
        const registeredUser = await Admin.register(user, password);

        console.log("User successfully registered:", registeredUser);

        // Respond with success
        res.status(201).json({ message: "Admin registered successfully" });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(400).json({ error: "Registration failed. Please try again." });
    }
});


app.get('/login', (req, res) => {
    res.render("login.ejs");
})


const rateLimit = require('express-rate-limit');

// Failed Login Attempts Tracker
const loginAttempts = {};


const loginLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute window for tracking login attempts
    max: 3, // Allow 3 attempts within this window
    message: "Too many failed login attempts. Please try again later.",
    handler: (req, res) => {
        const ip = req.ip;
        console.log(`Rate limit hit by IP: ${ip}`);

        // Check if lockout is already set for this IP
        if (loginAttempts[ip] && loginAttempts[ip].lockUntil > Date.now()) {
            return res.status(429).json({
                message: "Too many failed login attempts. Please try again later.",
            });
        }
    },
    keyGenerator: (req) => req.ip, // Track attempts based on IP address
    skip: (req) => {
        const ip = req.ip;

        // Initialize loginAttempts object if it doesn't exist for the IP
        if (!loginAttempts[ip]) {
            loginAttempts[ip] = { attempts: 0, lockUntil: null };
        }

        // Reset login attempts if lockout period has expired
        if (loginAttempts[ip].lockUntil && loginAttempts[ip].lockUntil < Date.now()) {
            loginAttempts[ip].attempts = 0; // Reset attempts
            loginAttempts[ip].lockUntil = null; // Reset lockUntil
            console.log(`Lockout expired for ${ip}. Attempts reset.`);
            return true;
        }

        // If max attempts are reached, set the lockout period
        if (loginAttempts[ip].attempts >= 3) {
            loginAttempts[ip].lockUntil = Date.now() + 1 * 60 * 1000; // Lockout for 1 minute
            console.log(`Locking out IP: ${ip} for 1 minute`);
            return false;
        }

        // Increment failed login attempts
        loginAttempts[ip].attempts += 1;

        return false; // Block further requests until lockout period expires
    },
});



app.post(
    '/login',
    loginLimiter,
    async (req, res, next) => {
        passport.authenticate('user-local', async (err, user, info) => {
            if (err) {
                console.error("Authentication error:", err);
                return res.status(500).json({ error: "Internal server error" });
            }
            
            if (!user) {
                // Wrong password or invalid credentials
                return res.status(401).json({ error: info?.message || "Invalid credentials" });
            }

            // Log the user in
            req.logIn(user, async (err) => {
                if (err) {
                    console.error("Login error:", err);
                    return res.status(500).json({ error: "Login failed" });
                }

                const ip = req.ip;
                console.log("User IP on successful login:", ip);

                // Reset login attempts after successful login
                if (loginAttempts[ip]) {
                    delete loginAttempts[ip]; // Clear any existing login attempts on success
                }

                // Store user ID and OTP status in the session
                req.session.userid = user.id;
                req.session.otpVerified = false;

                // Check if OTP secret already exists for the user
                if (!user.otpSecret) {
                    const otpSecret = otp.authenticator.generateSecret();
                    user.otpSecret = otpSecret;
                    user.lastLogin = Date.now();
                    try {
                        await user.save(); // Save OTP secret in the database
                    } catch (err) {
                        console.error("Error saving OTP secret:", err);
                        return res.status(500).json({ message: "Error setting up OTP" });
                    }

                    // Generate a QR code for Google Authenticator
                    const otpauthUrl = otp.authenticator.keyuri(user.email, 'SIVA', user.otpSecret);
                    QRCode.toDataURL(otpauthUrl, (err, dataUrl) => {
                        if (err) {
                            console.error("Error generating QR code:", err);
                            return res.status(500).json({ message: "Error generating QR code" });
                        }

                        console.log("Generated OTP QR code:", dataUrl);
                        return res.status(200).json({
                            message: "Login successful. Scan the QR code with Google Authenticator.",
                            qrCode: dataUrl,
                        });
                    });
                } else {
                    // Inform user to enter OTP
                    console.log("OTP secret already exists for user:", user.email);
                    return res.status(200).json({
                        message: "Login successful. Please enter the OTP from Google Authenticator.",
                    });
                }
            });
        })(req, res, next);
    }
);



app.post(
    '/adminlogin',
    loginLimiter,
    async (req, res, next) => {
        passport.authenticate('admin-local', async (err, user, info) => {
            if (err) {
                console.error("Authentication error:", err);
                return res.status(500).json({ error: "Internal server error" });
            }
            
            if (!user) {
                // Wrong password or invalid credentials
                return res.status(401).json({ error: info?.message || "Invalid credentials" });
            }

            // Log the user in
            req.logIn(user, async (err) => {
                if (err) {
                    console.error("Login error:", err);
                    return res.status(500).json({ error: "Login failed" });
                }

                const ip = req.ip;
                console.log("User IP on successful login:", ip);

                // Reset login attempts after successful login
                if (loginAttempts[ip]) {
                    delete loginAttempts[ip]; // Clear any existing login attempts on success
                }

                // Store user ID and OTP status in the session
                req.session.adminid = user.id;
                req.session.adminotpVerified = false;
                console.log("Session data after setting adminid:", req.session);
                console.log("Adminid:", user.id);

                // Check if OTP secret already exists for the user
                if (!user.otpSecret) {
                    const otpSecret = otp.authenticator.generateSecret();
                    user.otpSecret = otpSecret;
                    
                    try {
                        await user.save(); // Save OTP secret in the database
                    } catch (err) {
                        console.error("Error saving OTP secret:", err);
                        return res.status(500).json({ message: "Error setting up OTP" });
                    }

                    // Generate a QR code for Google Authenticator
                    const otpauthUrl = otp.authenticator.keyuri(user.email, 'SIVA', user.otpSecret);
                    QRCode.toDataURL(otpauthUrl, (err, dataUrl) => {
                        if (err) {
                            console.error("Error generating QR code:", err);
                            return res.status(500).json({ message: "Error generating QR code" });
                        }

                        console.log("Generated OTP QR code:", dataUrl);
                        return res.status(200).json({
                            message: "Login successful. Scan the QR code with Google Authenticator.",
                            qrCode: dataUrl,
                        });
                    });
                } else {
                    // Inform user to enter OTP
                    console.log("OTP secret already exists for user:", user.email);
                    return res.status(200).json({
                        message: "Login successful. Please enter the OTP from Google Authenticator.",
                    });
                }
            });
        })(req, res, next);
    }
);

app.get('/verify-otp', (req, res) => {
    res.render('verify-otp.ejs');
});

  

app.post('/verify-otp', async (req, res) => {
    try {
        const userId = req.session.userid; // Retrieve the logged-in user's ID from the session
        const userInputOtp = req.body.otp; // OTP entered by the user

        // Check if the user is logged in
        if (!userId) {
            return res.status(401).json({ message: "Unauthorized. Please log in first." });
        }

        // Retrieve the user's OTP secret from the database
        const user = await User.findById(userId);
        if (!user || !user.otpSecret) {
            return res.status(400).json({ message: "OTP setup not completed. Please contact support." });
        }

        // Validate the OTP using the stored secret
        const isValid = otp.authenticator.check(userInputOtp, user.otpSecret, { window: 1 }); // Allow a window for time differences


        if (isValid) {
            // Mark OTP as verified in the session
            req.session.otpVerified = true;
            console.log("OTP verified successfully for user:", user.email);

            return res.status(200).json({
                message: "OTP verified successfully. You are logged in.",
            });
        } else {
            console.log("Invalid OTP entered for user:", user.email);
            return res.status(400).json({ message: "Invalid OTP. Please try again." });
        }
    } catch (error) {
        console.error("Error verifying OTP:", error);
        res.status(500).json({ message: "Internal server error. Please try again later." });
    }
});

app.post('/adminverify-otp', async (req, res) => {
    try {
        console.log("Session in /adminverify-otp:", req.session);
        const adminid = req.session.adminid; // Retrieve the logged-in user's ID from the session
        const userInputOtp = req.body.otp; // OTP entered by the user
        console.log(adminid);
        // Check if the user is logged in
        if (!adminid) {
            console.log("not login by admin");
            return res.status(401).json({ message: "Unauthorized. Please log in first." });
        }

        // Retrieve the user's OTP secret from the database
        const user = await Admin.findById(adminid);
        console.log(user);
        if (!user || !user.otpSecret) {
            return res.status(400).json({ message: "OTP setup not completed. Please contact support." });
        }

        // Validate the OTP using the stored secret
        const isValid = otp.authenticator.check(userInputOtp, user.otpSecret, { window: 1 }); // Allow a window for time differences


        if (isValid) {
            // Mark OTP as verified in the session
            req.session.adminotpVerified = true;
            console.log("OTP verified successfully for user:", user.email);

            return res.status(200).json({
                message: "OTP verified successfully. You are logged in.",
            });
        } else {
            console.log("Invalid OTP entered for user:", user.email);
            return res.status(400).json({ message: "Invalid OTP. Please try again." });
        }
    } catch (error) {
        console.error("Error verifying OTP:", error);
        res.status(500).json({ message: "Internal server error. Please try again later." });
    }
});
  

const ensureOtpVerified = (req, res, next) => {
    console.log("Middleware executed");
    console.log("Session UserID:", req.session.userid);
    console.log("OTP Verified:", req.session.otpVerified);

    if (req.session.userid && req.session.otpVerified==true) {
        next(); // Proceed to the next middleware/route if OTP is verified
    } else {
        res.status(401).json({ message: "OTP not verified, please login." }); // Send an error response if OTP is not verified
    }
};

app.get("/profile",ensureOtpVerified ,(req, res) => {
    if (req.isAuthenticated()) {
        // Send user data as JSON if authenticated and OTP is verified
        console.log("this is profile page")
        res.json({
            isAuthenticated: true,
            user: req.user,
        });
    } else {
        // If not authenticated, send a 401 Unauthorized response
        res.status(401).json({
            isAuthenticated: false,
            message: "User not authenticated. Please log in.",
        });
    }
});

const ensureOtpVerified1 = (req, res, next) => {
    console.log("Middleware executed");
    console.log("Session UserID:", req.session.adminid);
    console.log("OTP Verified:", req.session.adminotpVerified);

    if (req.session.adminid && req.session.adminotpVerified==true) {
        next(); // Proceed to the next middleware/route if OTP is verified
    } else {
        res.status(401).json({ message: "OTP not verified, please login." }); // Send an error response if OTP is not verified
    }
};

app.get("/adminprofile",ensureOtpVerified1 ,(req, res) => {
    if (req.isAuthenticated()) {
        // Send user data as JSON if authenticated and OTP is verified
        console.log("this is profile page")
        res.json({
            isAuthenticated: true,
            user: req.user,
        });
    } else {
        // If not authenticated, send a 401 Unauthorized response
        res.status(401).json({
            isAuthenticated: false,
            message: "User not authenticated. Please log in.",
        });
    }
});


const upload = multer({ dest: "uploads/" });

// Route to handle adding a single email
app.post("/addSingleEmail", async (req, res) => {
  const { email } = req.body;
  console.log(req.session.adminid);
  if (!req.session.adminid) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const admin = await Admin.findById(req.session.adminid);

    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    if (admin.approvedEmails.includes(email)) {
      return res.status(400).json({ message: "Email already exists" });
    }

    admin.approvedEmails.push(email);
    await admin.save();

    return res.status(200).json({ message: "Email added successfully" });
  } catch (error) {
    console.error("Error adding single email:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Route to handle processing of uploaded Excel files
app.post(
  "/addExcelFile",
  upload.single("file"),
  async (req, res) => {
    console.log(req.session.adminid);
    if (!req.session.adminid) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const workbook = xlsx.readFile(req.file.path);
      const worksheet = workbook.Sheets[workbook.SheetNames[0]];
      const data = xlsx.utils.sheet_to_json(worksheet);

      const emails = data.map((row) => row.email).filter((email) => email);

      const admin = await Admin.findById(req.session.adminid);

      if (!admin) {
        return res.status(404).json({ message: "Admin not found" });
      }

      // Add unique emails to the approvedEmails array
      const newEmails = emails.filter(
        (email) => !admin.approvedEmails.includes(email)
      );

      admin.approvedEmails.push(...newEmails);
      await admin.save();

      return res.status(200).json({
        message: `${newEmails.length} emails added successfully`,
      });
    } catch (error) {
      console.error("Error processing Excel file:", error);
      return res.status(500).json({ message: "Error processing file" });
    }
  }
);

app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.session.destroy((err) => { // Destroy session
            if (err) {
                console.error("Error destroying session:", err);
                return res.status(500).json({ message: "Logout failed." });
            }
        res.clearCookie("connect.sid"); // Clear the session cookie
        res.status(200).send({ message: "Logged out successfully." }); // Send a response
        });
    });
});

app.get("/adminlogout", (req, res, next) => {
    req.logout((err) => { // Log out the user using Passport
        if (err) {
            return next(err);
        }

        req.session.destroy((err) => { // Destroy session
            if (err) {
                console.error("Error destroying session:", err);
                return res.status(500).json({ message: "Logout failed." });
            }

            res.clearCookie("connect.sid", { path: '/' }); // Ensure cookie is cleared for the same path
            res.status(200).json({ message: "Admin logged out successfully." });
        });
    });
});


app.get('/forgot-password', (req, res) => {
    res.render('forgot-password.ejs'); // Create a simple form for email input
});



app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "No account found with that email." });
          }

        // Generate a unique token and expiration time
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenExpiration = Date.now() + 60 * 60 * 1000; // 1-hour validity

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = tokenExpiration;
        await user.save();

        // Send the reset link via email
        const resetLink = `http://localhost:5173/reset-password/${resetToken}`;
        await transporter.sendMail({
            to: user.email,
            subject: 'Password Reset Request',
            text: `Click the link below to reset your password:\n\n${resetLink}`
        });

        console.log(`Password reset link sent to ${user.email}`);
        return res.status(200).json({ message: "Password reset link sent successfully." });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Internal server error." });
    }
});

app.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() } // Check if the token is still valid
        });

        if (!user) {
            return res.send("Password reset link is invalid or has expired.");
        }

        res.render('reset-password.ejs', { token });
    } catch (err) {
        console.error(err);
        res.send("An error occurred. Please try again.");
    }
});

app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Password reset link is invalid or has expired." });
        }

        // Update the user's password using Passport.js's setPassword method (if using passport-local-mongoose)
        await user.setPassword(password); // Assuming you're using passport-local-mongoose
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        console.log(`Password reset successful for ${user.email}`);
        res.status(200).json({ message: "Your password has been reset. You can now log in with the new password." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "An error occurred. Please try again." });
    }
});


app.all("*", (req, res, next) => {
    next(new ExpressError(404, "page not found!"));
});

app.use((err, req, res, next) => {
    let { status = 500, message = "Something went wrong" } = err;
    res.render("error.ejs", { message });
    //res.status(status).send(message);
});

app.listen(8080, () => {
    console.log("server is listening to port 8080");
});

