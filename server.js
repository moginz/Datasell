javascript
require('dotenv').config();
const express = require('express');
const path = require('path');
const admin = require('firebase-admin');
const axios = require('axios');
const session = require('express-session');

// Initialize app FIRST
const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
;

// ====================
// RENDER OPTIMIZATIONS & DOMAIN SECURITY
// ====================

// ✅ APPROVED DOMAINS - UPDATE WITH YOUR ACTUAL RENDER DOMAIN
const APPROVED_DOMAINS = [
    'https://datasell.onrender.com',      // ← CHANGE THIS TO YOUR ACTUAL RENDER DOMAIN
    'https://www.yourdomain.com',         // Keep for future custom domain
    'http://localhost:3000'               // Development only
];

// ✅ RENDER COLD START HANDLING
const APP_START_TIME = Date.now();
let isColdStart = true;
setTimeout(() => {
    isColdStart = false;
    console.log('🔥 App warmed up - cold start period ended');
}, 120000);

// ✅ DOMAIN VALIDATION MIDDLEWARE
const validateDomain = (req, res, next) => {
    // Skip for health checks and static files
    if (req.path === '/api/health' || req.path.startsWith('/public/') || req.path === '/') {
        return next();
    }
    
    const host = req.get('host');
    const origin = req.get('origin');
    const referer = req.get('referer');
    
    // Allow requests without origin (like mobile apps or curl)
    if (!origin && !referer) {
        return next();
    }
    
    const requestUrl = origin || referer || `http://${host}`;
    const isApproved = APPROVED_DOMAINS.some(domain => 
        requestUrl.includes(domain.replace('https://', '').replace('http://', ''))
    );
    
    if (!isApproved) {
        console.log('🚨 UNAUTHORIZED DOMAIN ACCESS ATTEMPT:', {
            host,
            origin,
            referer,
            ip: req.ip,
            path: req.path,
            timestamp: new Date().toISOString()
        });
        
        // For API routes, return JSON error
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({
                success: false,
                error: 'Access denied. Unauthorized domain.'
            });
        }
        
        // For page routes, redirect to login
        return res.redirect('/login');
    }
    
    next();
};

// ✅ CRITICAL OPERATIONS SECURITY
const requireSecureDomain = (req, res, next) => {
    const criticalEndpoints = [
        '/api/purchase-data',
        '/api/initialize-payment',
        '/api/initialize-direct-payment',
        '/api/verify-payment',
        '/api/process-direct-purchase'
    ];
    
    if (criticalEndpoints.includes(req.path) && process.env.NODE_ENV === 'production') {
        if (isColdStart) {
            return res.status(503).json({
                success: false,
                error: 'Service starting up. Please try again in 30 seconds.',
                retryAfter: 30
            });
        }
    }
    
    next();
};

// ✅ KEEP-ALIVE SERVICE FOR RENDER
const startKeepAlive = () => {
    if (process.env.NODE_ENV === 'production') {
        setInterval(() => {
            axios.get(`${process.env.BASE_URL || 'http://localhost:3000'}/api/health`)
                .then(() => console.log('🔄 Keep-alive ping sent'))
                .catch(() => console.log('❌ Keep-alive ping failed'));
        }, 10 * 60 * 1000); // Every 10 minutes
    }
};

// ====================
// SECURITY & MIDDLEWARE SETUP
// ====================

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    crossOriginEmbedderPolicy: false
}));

// CORS configuration with domain validation
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        // Check if origin is in approved list
        if (APPROVED_DOMAINS.some(domain => origin.includes(domain.replace('https://', '').replace('http://', '')))) {
            callback(null, true);
        } else {
            console.log('🚨 CORS BLOCKED:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

// Trust proxy for rate limiting in production
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

// Apply domain security middleware
app.use(validateDomain);
app.use(requireSecureDomain);

// Rate limiting configurations
const createRateLimiter = (windowMs, max, message) => rateLimit({
    windowMs,
    max,
    message: { success: false, error: message },
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply different rate limits based on endpoints
const generalLimiter = createRateLimiter(15 * 60 * 1000, 100, 'Too many requests, please try again later.');
const authLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many authentication attempts. Please try again later.');
const purchaseLimiter = createRateLimiter(1 * 60 * 1000, 3, 'Too many purchase attempts. Please wait 1 minute.');
const walletLimiter = createRateLimiter(5 * 60 * 1000, 5, 'Too many wallet operations. Please wait 5 minutes.');
const adminLimiter = createRateLimiter(1 * 60 * 1000, 30, 'Too many admin requests. Please slow down.');

// Apply general rate limiting to all routes
app.use(generalLimiter);

// Static files and body parsing
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    },
    name: 'datasell.sid'
}));

// Enhanced Request logging middleware with domain info
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`📨 ${timestamp} - ${req.method} ${req.originalUrl} - IP: ${req.ip} - Origin: ${req.get('origin') || 'none'}`);
    next();
});

// ====================
// VALIDATION MIDDLEWARES
// ====================

const validatePurchase = (req, res, next) => {
    const { network, phoneNumber, amount, packageName } = req.body;
    
    const errors = [];
    
    if (!['mtn', 'at'].includes(network)) {
        errors.push('Invalid network. Must be "mtn" or "at".');
    }
    
    if (!phoneNumber || !/^0(?:23|24|25|26|27|28|29|54|55|56|57|59)\d{7}$/.test(phoneNumber)) {
        errors.push('Invalid Ghana phone number format. Must be 10 digits starting with 02 or 05.');
    }
    
    if (!amount || amount <= 0 || amount > 10000) {
        errors.push('Invalid amount. Must be between ₵0.10 and ₵10,000.');
    }
    
    if (!packageName || packageName.trim().length === 0) {
        errors.push('Package name is required.');
    }
    
    if (errors.length > 0) {
        return res.status(400).json({ 
            success: false, 
            error: errors.join(' ') 
        });
    }
    
    next();
};

const validateWalletFunding = (req, res, next) => {
    const { amount } = req.body;
    
    if (!amount || amount < 1 || amount > 5000) {
        return res.status(400).json({ 
            success: false, 
            error: 'Invalid amount. Must be between ₵1 and ₵5,000.' 
        });
    }
    
    next();
};

const validateDirectPayment = (req, res, next) => {
    const { amount, phoneNumber, network, packageName } = req.body;
    
    const errors = [];
    
    if (!amount || amount <= 0 || amount > 10000) {
        errors.push('Invalid amount. Must be between ₵0.10 and ₵10,000.');
    }
    
    if (!phoneNumber || !/^0(?:23|24|25|26|27|28|29|54|55|56|57|59)\d{7}$/.test(phoneNumber)) {
        errors.push('Invalid Ghana phone number.');
    }
    
    if (!['mtn', 'at'].includes(network)) {
        errors.push('Invalid network.');
    }
    
    if (!packageName || packageName.trim().length === 0) {
        errors.push('Package name is required.');
    }
    
    if (errors.length > 0) {
        return res.status(400).json({ 
            success: false, 
            error: errors.join(' ') 
        });
    }
    
    next();
};

// ====================
// ENVIRONMENT VALIDATION
// ====================

const requiredEnvVars = [
    'FIREBASE_PRIVATE_KEY',
    'FIREBASE_CLIENT_EMAIL', 
    'FIREBASE_DATABASE_URL',
    'PAYSTACK_SECRET_KEY',
    'HUBNET_API_KEY',
    'SESSION_SECRET',
    'BASE_URL'
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
if (missingEnvVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
    process.exit(1);
}

// Validate BASE_URL is in approved domains
if (process.env.BASE_URL && !APPROVED_DOMAINS.includes(process.env.BASE_URL)) {
    console.warn('⚠️  WARNING: BASE_URL not in approved domains:', process.env.BASE_URL);
}

// ====================
// FIREBASE INITIALIZATION
// ====================

const serviceAccount = {
    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

try {
    if (admin.apps.length === 0) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            databaseURL: process.env.FIREBASE_DATABASE_URL
        });
    }
    console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
    console.error('❌ Firebase initialization failed:', error.message);
    process.exit(1);
}

// ====================
// PACKAGE CACHE SYSTEM
// ====================

const packageCache = {
    mtn: null,
    at: null,
    lastUpdated: null
};

const initializePackageCache = () => {
    console.log('🔄 Initializing real-time package cache...');
    
    const setupPackageListener = (network) => {
        admin.database().ref(`packages/${network}`).on('value', (snapshot) => {
            const packages = snapshot.val() || {};
            const packagesArray = Object.entries(packages)
                .map(([key, pkg]) => ({ id: key, ...pkg }))
                .filter(pkg => pkg.active !== false)
                .sort((a, b) => {
                    const getVolume = (pkg) => {
                        if (pkg.name) {
                            const volumeMatch = pkg.name.match(/\d+/);
                            return volumeMatch ? parseInt(volumeMatch[0]) : 0;
                        }
                        return 0;
                    };
                    return getVolume(a) - getVolume(b);
                });
            
            packageCache[network] = packagesArray;
            packageCache.lastUpdated = Date.now();
            console.log(`✅ ${network.toUpperCase()} packages cache updated (${packagesArray.length} packages)`);
        });
    };
    
    setupPackageListener('mtn');
    setupPackageListener('at');
};

initializePackageCache();

// ====================
// AUTHENTICATION MIDDLEWARES
// ====================

const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ 
            success: false, 
            error: 'Authentication required' 
        });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.isAdmin) {
        next();
    } else {
        res.status(403).json({ 
            success: false, 
            error: 'Admin access required' 
        });
    }
};

// ====================
// UTILITY FUNCTIONS
// ====================

const generateReference = (prefix = 'DS') => {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
};

const convertVolumeToMB = (volume) => {
    if (!volume) return '1000';
    
    const volumeNumber = parseInt(volume);
    if (volumeNumber < 100) {
        return (volumeNumber * 1000).toString();
    }
    return volume.toString();
};

const logTransaction = async (type, data) => {
    try {
        const logRef = admin.database().ref('transactionLogs').push();
        await logRef.set({
            type,
            ...data,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Failed to log transaction:', error);
    }
};

// ====================
// PAGE ROUTES
// ====================

const pageRoutes = [
    { path: '/', file: 'index.html', auth: true },
    { path: '/login', file: 'login.html', auth: false, redirectIfAuth: true },
    { path: '/signup', file: 'signup.html', auth: false, redirectIfAuth: true },
    { path: '/purchase', file: 'purchase.html', auth: true },
    { path: '/wallet', file: 'wallet.html', auth: true },
    { path: '/orders', file: 'orders.html', auth: true },
    { path: '/profile', file: 'profile.html', auth: true },
    { path: '/admin-login', file: 'admin-login.html', auth: false, redirectIfAuth: true },
    { path: '/admin', file: 'admin.html', auth: true, admin: true },
    { path: '/verify-direct-payment', file: 'verify-payment.html', auth: true }
];

pageRoutes.forEach(route => {
    app.get(route.path, (req, res, next) => {
        if (route.auth && !req.session.user) {
            return res.redirect('/login');
        }
        if (route.redirectIfAuth && req.session.user) {
            return res.redirect('/');
        }
        if (route.admin && (!req.session.user || !req.session.user.isAdmin)) {
            return res.redirect('/admin-login');
        }
        res.sendFile(path.join(__dirname, 'public', route.file));
    });
});

// ====================
// AUTHENTICATION API ROUTES
// ====================

app.post('/api/signup', authLimiter, async (req, res) => {
    try {
        const { email, password, firstName, lastName, phone } = req.body;
        
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ 
                success: false, 
                error: 'All fields are required' 
            });
        }

        const userRecord = await admin.auth().createUser({
            email,
            password,
            displayName: `${firstName} ${lastName}`,
            phoneNumber: phone
        });

        const userData = {
            firstName,
            lastName,
            email,
            phone: phone || '',
            walletBalance: 0,
            createdAt: new Date().toISOString(),
            isAdmin: email === process.env.ADMIN_EMAIL
        };

        await admin.database().ref('users/' + userRecord.uid).set(userData);

        await logTransaction('user_signup', {
            userId: userRecord.uid,
            email,
            firstName,
            lastName
        });

        res.json({ 
            success: true, 
            userId: userRecord.uid,
            message: 'Account created successfully'
        });
    } catch (error) {
        console.error('Signup error:', error);
        
        let errorMessage = 'Registration failed';
        if (error.code === 'auth/email-already-exists') {
            errorMessage = 'Email already registered';
        } else if (error.code === 'auth/invalid-email') {
            errorMessage = 'Invalid email address';
        } else if (error.code === 'auth/weak-password') {
            errorMessage = 'Password should be at least 6 characters';
        }
        
        res.status(400).json({ 
            success: false, 
            error: errorMessage 
        });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password are required' 
            });
        }

        // Admin login
        if (email === process.env.ADMIN_EMAIL) {
            if (password === process.env.ADMIN_PASSWORD) {
                let userRecord;
                try {
                    userRecord = await admin.auth().getUserByEmail(email);
                } catch (error) {
                    userRecord = await admin.auth().createUser({
                        email,
                        password: process.env.ADMIN_PASSWORD,
                        displayName: 'Administrator'
                    });

                    await admin.database().ref('users/' + userRecord.uid).set({
                        firstName: 'Admin',
                        lastName: 'User',
                        email,
                        phone: '',
                        walletBalance: 0,
                        createdAt: new Date().toISOString(),
                        isAdmin: true
                    });
                }

                req.session.user = {
                    uid: userRecord.uid,
                    email: userRecord.email,
                    displayName: userRecord.displayName,
                    isAdmin: true
                };

                await logTransaction('admin_login', { userId: userRecord.uid });

                return res.json({ 
                    success: true, 
                    message: 'Admin login successful',
                    user: req.session.user
                });
            } else {
                return res.status(401).json({ 
                    success: false, 
                    error: 'Invalid admin credentials' 
                });
            }
        }

        // Regular user login
        const signInResponse = await axios.post(
            `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_API_KEY}`,
            {
                email,
                password,
                returnSecureToken: true
            },
            { timeout: 10000 }
        );

        const { localId, email: userEmail, displayName } = signInResponse.data;

        const userSnapshot = await admin.database().ref('users/' + localId).once('value');
        const userData = userSnapshot.val();

        if (!userData) {
            return res.status(404).json({ 
                success: false, 
                error: 'User data not found' 
            });
        }

        req.session.user = {
            uid: localId,
            email: userEmail,
            displayName: displayName || `${userData.firstName} ${userData.lastName}`,
            isAdmin: userData.isAdmin || false
        };

        await logTransaction('user_login', { userId: localId });

        res.json({ 
            success: true, 
            message: 'Login successful',
            user: req.session.user
        });
    } catch (error) {
        console.error('Login error:', error);
        
        let errorMessage = 'Login failed';
        if (error.response?.data?.error?.message) {
            const firebaseError = error.response.data.error.message;
            if (firebaseError.includes('INVALID_EMAIL') || firebaseError.includes('INVALID_LOGIN_CREDENTIALS')) {
                errorMessage = 'Invalid email or password';
            } else if (firebaseError.includes('TOO_MANY_ATTEMPTS_TRY_LATER')) {
                errorMessage = 'Too many login attempts. Please try again later.';
            }
        }
        
        res.status(401).json({ 
            success: false, 
            error: errorMessage 
        });
    }
});

app.get('/api/user', requireAuth, (req, res) => {
    res.json({ 
        success: true, 
        user: req.session.user 
    });
});

app.post('/api/logout', requireAuth, (req, res) => {
    const userId = req.session.user.uid;
    
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ success: false, error: 'Logout failed' });
        }
        
        logTransaction('user_logout', { userId });
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

// ====================
// WALLET & PAYMENT ROUTES
// ====================

app.get('/api/wallet/balance', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.uid;
        const userSnapshot = await admin.database().ref('users/' + userId).once('value');
        const userData = userSnapshot.val();
        
        if (!userData) {
            return res.status(404).json({ 
                success: false, 
                error: 'User not found' 
            });
        }

        res.json({ 
            success: true, 
            balance: userData.walletBalance || 0 
        });
    } catch (error) {
        console.error('Wallet balance error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch wallet balance' 
        });
    }
});

app.get('/api/wallet/transactions', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.uid;
        
        const [transactionsSnapshot, paymentsSnapshot] = await Promise.all([
            admin.database()
                .ref('transactions')
                .orderByChild('userId')
                .equalTo(userId)
                .once('value'),
            admin.database()
                .ref('payments')
                .orderByChild('userId')
                .equalTo(userId)
                .once('value')
        ]);

        const transactions = transactionsSnapshot.val() || {};
        const payments = paymentsSnapshot.val() || {};

        let allTransactions = [];

        // Add data purchases
        Object.entries(transactions).forEach(([id, transaction]) => {
            allTransactions.push({
                id,
                type: 'purchase',
                description: `${transaction.packageName} - ${transaction.network?.toUpperCase() || ''}`,
                amount: -transaction.amount,
                status: transaction.status || 'success',
                timestamp: transaction.timestamp,
                reference: transaction.reference
            });
        });

        // Add wallet funding
        Object.entries(payments).forEach(([id, payment]) => {
            allTransactions.push({
                id,
                type: 'funding',
                description: 'Wallet Funding',
                amount: payment.amount,
                status: payment.status || 'success',
                timestamp: payment.timestamp,
                reference: payment.reference
            });
        });

        // Sort by timestamp (newest first) and limit
        allTransactions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        allTransactions = allTransactions.slice(0, 20);

        res.json({ success: true, transactions: allTransactions });
    } catch (error) {
        console.error('Wallet transactions error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load transactions' 
        });
    }
});

app.post('/api/initialize-payment', requireAuth, walletLimiter, validateWalletFunding, async (req, res) => {
    try {
        const { amount } = req.body;
        const userId = req.session.user.uid;
        const email = req.session.user.email;
        
        const reference = generateReference('WALLET');

        const paystackResponse = await axios.post(
            `${process.env.PAYSTACK_BASE_URL}/transaction/initialize`,
            {
                email,
                amount: amount * 100,
                callback_url: `${process.env.BASE_URL}/wallet?success=true`,
                metadata: {
                    userId,
                    purpose: 'wallet_funding',
                    reference
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                },
                timeout: 15000
            }
        );

        await logTransaction('wallet_funding_init', {
            userId,
            amount,
            reference,
            paystackReference: paystackResponse.data.data.reference
        });

        res.json(paystackResponse.data);
    } catch (error) {
        console.error('Paystack initialization error:', error);
        
        let errorMessage = 'Payment initialization failed';
        if (error.response?.data?.message) {
            errorMessage = error.response.data.message;
        }
        
        res.status(500).json({ 
            success: false, 
            error: errorMessage 
        });
    }
});

app.get('/api/verify-payment/:reference', requireAuth, async (req, res) => {
    try {
        const { reference } = req.params;
        const userId = req.session.user.uid;
        
        const paystackResponse = await axios.get(
            `${process.env.PAYSTACK_BASE_URL}/transaction/verify/${reference}`,
            {
                headers: {
                    'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
                },
                timeout: 15000
            }
        );

        const result = paystackResponse.data;
        
        if (result.data.status === 'success') {
            const amount = result.data.amount / 100;
            
            const userRef = admin.database().ref('users/' + userId);
            const userSnapshot = await userRef.once('value');
            const userData = userSnapshot.val();
            
            if (!userData) {
                return res.status(404).json({ 
                    success: false, 
                    error: 'User not found' 
                });
            }

            const currentBalance = userData.walletBalance || 0;
            const newBalance = currentBalance + amount;
            
            await userRef.update({ walletBalance: newBalance });

            const paymentRef = admin.database().ref('payments').push();
            await paymentRef.set({
                userId,
                amount,
                reference,
                status: 'success',
                paystackData: result.data,
                timestamp: new Date().toISOString()
            });

            await logTransaction('wallet_funding_success', {
                userId,
                amount,
                reference,
                previousBalance: currentBalance,
                newBalance
            });

            res.json({ 
                success: true, 
                amount,
                newBalance,
                message: 'Wallet funded successfully!'
            });
        } else {
            await logTransaction('wallet_funding_failed', {
                userId,
                reference,
                status: result.data.status
            });
            
            res.json({ 
                success: false, 
                error: 'Payment failed or pending' 
            });
        }
    } catch (error) {
        console.error('Payment verification error:', error);
        
        await logTransaction('wallet_funding_error', {
            userId: req.session.user.uid,
            reference: req.params.reference,
            error: error.message
        });
        
        res.status(500).json({ 
            success: false, 
            error: 'Payment verification failed' 
        });
    }
});

// ====================
// DATA PURCHASE ROUTES
// ====================

app.get('/api/packages/:network', requireAuth, async (req, res) => {
    try {
        const { network } = req.params;
        
        if (!['mtn', 'at'].includes(network)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid network' 
            });
        }

        if (!packageCache[network]) {
            const packagesSnapshot = await admin.database().ref('packages/' + network).once('value');
            const packages = packagesSnapshot.val() || {};
            const packagesArray = Object.values(packages).filter(pkg => pkg.active !== false);
            
            packagesArray.sort((a, b) => {
                const getVolume = (pkg) => {
                    if (pkg.name) {
                        const volumeMatch = pkg.name.match(/\d+/);
                        return volumeMatch ? parseInt(volumeMatch[0]) : 0;
                    }
                    return 0;
                };
                return getVolume(a) - getVolume(b);
            });
            
            packageCache[network] = packagesArray;
        }
        
        res.json({ 
            success: true, 
            packages: packageCache[network] || []
        });
    } catch (error) {
        console.error('Packages fetch error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch packages' 
        });
    }
});

app.post('/api/purchase-data', requireAuth, purchaseLimiter, validatePurchase, async (req, res) => {
    try {
        const { network, volume, phoneNumber, amount, packageName } = req.body;
        const userId = req.session.user.uid;
        
        console.log('🔄 Purchase request:', { network, volume, phoneNumber, amount, packageName });

        // Convert volume to MB for Hubtel
        const volumeMB = convertVolumeToMB(volume);
        console.log(`🔢 Volume converted: ${volume} → ${volumeMB}MB`);

        // Check user balance
        const userRef = admin.database().ref('users/' + userId);
        const userSnapshot = await userRef.once('value');
        const userData = userSnapshot.val();
        
        if (!userData || userData.walletBalance < amount) {
            return res.status(400).json({ 
                success: false, 
                error: 'Insufficient wallet balance' 
            });
        }

        const reference = generateReference('PURCHASE');
        
        // Hubnet API call
        const hubnetResponse = await axios.post(
            `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`,
            {
                phone: phoneNumber,
                volume: volumeMB,
                reference: reference,
                referrer: userData.phone,
                webhook: `${process.env.BASE_URL}/api/hubnet-webhook`
            },
            {
                headers: {
                    'token': `Bearer ${process.env.HUBNET_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                timeout: 30000
            }
        );

        const hubnetData = hubnetResponse.data;
        console.log('📡 Hubnet response:', hubnetData);

        if (hubnetData.status === true && hubnetData.code === "0000") {
            const newBalance = userData.walletBalance - amount;
            await userRef.update({ walletBalance: newBalance });

            const transactionRef = admin.database().ref('transactions').push();
            await transactionRef.set({
                userId,
                network,
                packageName,
                volume: volumeMB,
                phoneNumber,
                amount,
                status: 'success',
                reference,
                transactionId: hubnetData.transaction_id,
                hubnetResponse: hubnetData,
                timestamp: new Date().toISOString()
            });

            await logTransaction('data_purchase_success', {
                userId,
                network,
                packageName,
                amount,
                volume: volumeMB,
                phoneNumber,
                reference,
                hubnetTransactionId: hubnetData.transaction_id
            });

            res.json({ 
                success: true, 
                data: hubnetData,
                newBalance,
                message: 'Data purchase successful!'
            });
        } else {
            await logTransaction('data_purchase_failed', {
                userId,
                network,
                packageName,
                amount,
                phoneNumber,
                reference,
                hubnetCode: hubnetData.code,
                hubnetReason: hubnetData.reason
            });

            res.status(400).json({ 
                success: false, 
                error: hubnetData.reason || 'Purchase failed',
                hubnetCode: hubnetData.code
            });
        }
    } catch (error) {
        console.error('❌ Purchase error:', error);
        
        let errorMessage = 'Purchase failed';
        if (error.response) {
            errorMessage = error.response.data?.reason || error.response.data?.message || error.message;
        }
        
        await logTransaction('data_purchase_error', {
            userId: req.session.user.uid,
            error: errorMessage,
            ...req.body
        });
        
        res.status(500).json({ 
            success: false, 
            error: errorMessage 
        });
    }
});

app.post('/api/initialize-direct-payment', requireAuth, purchaseLimiter, validateDirectPayment, async (req, res) => {
    try {
        const { amount, phoneNumber, network, packageName } = req.body;
        const userId = req.session.user.uid;
        const email = req.session.user.email;

        const reference = generateReference('DIRECT');

        const paystackResponse = await axios.post(
            `${process.env.PAYSTACK_BASE_URL}/transaction/initialize`,
            {
                email,
                amount: amount * 100,
                callback_url: `${process.env.BASE_URL}/verify-direct-payment`,
                metadata: {
                    userId,
                    phoneNumber,
                    network,
                    packageName,
                    purpose: 'direct_data_purchase',
                    reference
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                },
                timeout: 15000
            }
        );

        const paystackData = paystackResponse.data;

        await logTransaction('direct_payment_init', {
            userId,
            amount,
            network,
            packageName,
            phoneNumber,
            reference,
            paystackReference: paystackData.data.reference
        });

        res.json({
            status: true,
            message: 'Payment initialized successfully',
            data: {
                authorization_url: paystackData.data.authorization_url,
                reference: paystackData.data.reference
            }
        });

    } catch (error) {
        console.error('❌ Direct payment initialization error:', error);
        
        let errorMessage = 'Payment initialization failed';
        if (error.response?.data?.message) {
            errorMessage = error.response.data.message;
        }
        
        res.status(500).json({ 
            success: false, 
            error: errorMessage 
        });
    }
});

app.get('/api/process-direct-purchase/:reference', requireAuth, async (req, res) => {
    try {
        const { reference } = req.params;
        const userId = req.session.user.uid;

        console.log('🔍 Processing direct purchase for reference:', reference);

        const paystackResponse = await axios.get(
            `${process.env.PAYSTACK_BASE_URL}/transaction/verify/${reference}`,
            {
                headers: {
                    'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
                },
                timeout: 15000
            }
        );

        const result = paystackResponse.data;

        if (result.data.status === 'success') {
            const amount = result.data.amount / 100;
            const { phoneNumber, network, packageName } = result.data.metadata;

            console.log('📦 Purchase details:', { phoneNumber, network, packageName, amount });

            // Convert volume to MB
            const volumeMB = convertVolumeToMB(packageName);
            console.log(`🔢 Direct purchase volume: ${volumeMB}MB`);

            const hubnetResponse = await axios.post(
                `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`,
                {
                    phone: phoneNumber,
                    volume: volumeMB,
                    reference: reference,
                    webhook: `${process.env.BASE_URL}/api/hubnet-webhook`
                },
                {
                    headers: {
                        'token': `Bearer ${process.env.HUBNET_API_KEY}`,
                        'Content-Type': 'application/json'
                    },
                    timeout: 30000
                }
            );

            const hubnetData = hubnetResponse.data;
            console.log('📡 Hubnet response:', hubnetData);

            if (hubnetData.status === true && hubnetData.code === "0000") {
                const transactionRef = admin.database().ref('transactions').push();
                await transactionRef.set({
                    userId,
                    network,
                    packageName,
                    volume: volumeMB,
                    phoneNumber,
                    amount,
                    status: 'success',
                    reference,
                    transactionId: hubnetData.transaction_id,
                    hubnetResponse: hubnetData,
                    paymentMethod: 'direct',
                    timestamp: new Date().toISOString()
                });

                await logTransaction('direct_purchase_success', {
                    userId,
                    network,
                    packageName,
                    amount,
                    phoneNumber,
                    reference,
                    hubnetTransactionId: hubnetData.transaction_id
                });

                res.json({ 
                    success: true, 
                    message: 'Data purchase successful!',
                    data: hubnetData
                });
            } else {
                console.error('❌ Hubnet purchase failed:', hubnetData);
                
                await logTransaction('direct_purchase_hubnet_failed', {
                    userId,
                    reference,
                    hubnetCode: hubnetData.code,
                    hubnetReason: hubnetData.reason
                });
                
                throw new Error(hubnetData.reason || `Hubnet error: ${hubnetData.code}`);
            }
        } else {
            throw new Error('Payment verification failed');
        }
    } catch (error) {
        console.error('❌ Direct purchase processing error:', error);
        
        let errorMessage = 'Purchase processing failed';
        if (error.response) {
            errorMessage = error.response.data?.reason || error.response.data?.message || error.message;
        }
        
        await logTransaction('direct_purchase_error', {
            userId: req.session.user.uid,
            reference: req.params.reference,
            error: errorMessage
        });
        
        res.status(500).json({ 
            success: false, 
            error: errorMessage,
            details: 'Failed to process data purchase after payment'
        });
    }
});

// ====================
// HUBNET WEBHOOK
// ====================

app.post('/api/hubnet-webhook', express.json(), async (req, res) => {
    try {
        const { reference, status, message, transaction_id } = req.body;
        
        console.log('📨 Hubnet webhook received:', { reference, status, message, transaction_id });

        // Find transaction by reference
        const transactionsSnapshot = await admin.database()
            .ref('transactions')
            .orderByChild('reference')
            .equalTo(reference)
            .once('value');

        if (transactionsSnapshot.exists()) {
            const transactionKey = Object.keys(transactionsSnapshot.val())[0];
            const updates = {
                hubnetStatus: status,
                hubnetMessage: message,
                updatedAt: new Date().toISOString()
            };

            // Update status based on webhook
            if (status === 'success') {
                updates.status = 'success';
            } else if (status === 'failed') {
                updates.status = 'failed';
            }

            await admin.database().ref(`transactions/${transactionKey}`).update(updates);

            await logTransaction('hubnet_webhook', {
                reference,
                status,
                message,
                transaction_id,
                transactionKey
            });
        }

        res.status(200).json({ success: true });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({ success: false });
    }
});

app.get('/api/hubnet-balance', requireAuth, async (req, res) => {
    try {
        const response = await axios.get(
            'https://console.hubnet.app/live/api/context/business/transaction/check_balance',
            {
                headers: {
                    'token': `Bearer ${process.env.HUBNET_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                timeout: 10000
            }
        );

        res.json({ 
            success: true, 
            balance: response.data 
        });
    } catch (error) {
        console.error('Hubnet balance error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch Hubnet balance' 
        });
    }
});

// ====================
// USER PROFILE ROUTES
// ====================

app.get('/api/profile', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.uid;
        const userSnapshot = await admin.database().ref('users/' + userId).once('value');
        const userData = userSnapshot.val();
        
        if (!userData) {
            return res.status(404).json({ 
                success: false, 
                error: 'User profile not found' 
            });
        }

        res.json({ 
            success: true, 
            profile: userData 
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch profile' 
        });
    }
});

app.get('/api/profile/stats', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.uid;
        
        const ordersSnapshot = await admin.database()
            .ref('transactions')
            .orderByChild('userId')
            .equalTo(userId)
            .once('value');
        
        const orders = ordersSnapshot.val() || {};
        const ordersArray = Object.values(orders);
        
        const stats = {
            totalOrders: ordersArray.length,
            successfulOrders: ordersArray.filter(order => order.status === 'success').length,
            totalSpent: ordersArray.reduce((total, order) => total + (order.amount || 0), 0),
            successRate: ordersArray.length > 0 ? 
                (ordersArray.filter(order => order.status === 'success').length / ordersArray.length * 100).toFixed(1) : 0
        };

        res.json({ 
            success: true, 
            stats: stats 
        });
    } catch (error) {
        console.error('Profile stats error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch profile stats' 
        });
    }
});

app.get('/api/orders', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.uid;
        
        const ordersSnapshot = await admin.database()
            .ref('transactions')
            .orderByChild('userId')
            .equalTo(userId)
            .once('value');
        
        const orders = ordersSnapshot.val() || {};
        
        const ordersArray = Object.values(orders)
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        res.json({ 
            success: true, 
            orders: ordersArray 
        });
    } catch (error) {
        console.error('Orders error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch orders' 
        });
    }
});

// ====================
// ADMIN ROUTES (SIMPLIFIED FOR BREVITY)
// ====================

// Apply admin rate limiting to all admin routes
app.use('/api/admin/*', requireAdmin, adminLimiter);

app.get('/api/admin/dashboard/stats', requireAdmin, async (req, res) => {
    try {
        const [usersSnapshot, transactionsSnapshot, paymentsSnapshot] = await Promise.all([
            admin.database().ref('users').once('value'),
            admin.database().ref('transactions').once('value'),
            admin.database().ref('payments').once('value')
        ]);

        const users = usersSnapshot.val() || {};
        const transactions = transactionsSnapshot.val() || {};
        const payments = paymentsSnapshot.val() || {};

        const usersArray = Object.values(users);
        const transactionsArray = Object.values(transactions);
        const paymentsArray = Object.values(payments);

        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);

        const todayTransactions = transactionsArray.filter(t => new Date(t.timestamp) >= today);
        const weekTransactions = transactionsArray.filter(t => new Date(t.timestamp) >= weekAgo);

        const totalRevenue = paymentsArray.reduce((sum, payment) => sum + (payment.amount || 0), 0);
        const todayRevenue = todayTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);
        const weekRevenue = weekTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);

        const stats = {
            totalUsers: usersArray.length,
            totalTransactions: transactionsArray.length,
            totalRevenue,
            successfulTransactions: transactionsArray.filter(t => t.status === 'success').length,
            todayTransactions: todayTransactions.length,
            todayRevenue,
            weekRevenue,
            newUsers: usersArray.filter(u => new Date(u.createdAt) >= weekAgo).length,
            successRate: transactionsArray.length > 0 ? 
                (transactionsArray.filter(t => t.status === 'success').length / transactionsArray.length * 100).toFixed(1) : 0
        };

        res.json({ success: true, stats });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add other admin routes here (users, packages, transactions, etc.)
// ... (your existing admin routes can be added here)

// ====================
// HEALTH & ERROR HANDLING
// ====================

// Enhanced health check with Render info
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV,
        coldStart: isColdStart,
        approvedDomains: APPROVED_DOMAINS,
        version: '1.0.0',
        services: {
            firebase: 'Connected',
            paystack: process.env.PAYSTACK_SECRET_KEY ? 'Configured' : 'Missing',
            hubnet: process.env.HUBNET_API_KEY ? 'Configured' : 'Missing'
        }
    });
});

// Security info endpoint (for admin debugging)
app.get('/api/security/info', requireAdmin, (req, res) => {
    res.json({
        approvedDomains: APPROVED_DOMAINS,
        currentDomain: req.get('host'),
        origin: req.get('origin'),
        environment: process.env.NODE_ENV,
        coldStart: isColdStart
    });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'API endpoint not found' 
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('🚨 Unhandled Error:', {
        message: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        timestamp: new Date().toISOString()
    });
    
    // Don't leak error details in production
    const errorResponse = {
        success: false, 
        error: 'Internal server error'
    };
    
    if (process.env.NODE_ENV !== 'production') {
        errorResponse.details = error.message;
        errorResponse.stack = error.stack;
    }
    
    res.status(500).json(errorResponse);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received, shutting down gracefully');
    process.exit(0);
});

// Start server with enhanced logging
app.listen(PORT, () => {
    console.log(`🚀 DataSell server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV}`);
    console.log(`🌐 Base URL: ${process.env.BASE_URL}`);
    console.log(`🔥 Firebase Project: ${process.env.FIREBASE_PROJECT_ID}`);
    console.log(`📡 Hubnet API: Integrated`);
    console.log(`💳 Paystack: Live Mode`);
    console.log(`🛡️  SECURITY: Domain validation ENABLED`);
    console.log(`✅ Approved domains: ${APPROVED_DOMAINS.join(', ')}`);
    console.log(`🔄 Keep-alive service: ${process.env.NODE_ENV === 'production' ? 'ACTIVE' : 'INACTIVE'}`);
    console.log(`👑 Admin Panel: Ready at /admin`);
    
    // Start keep-alive in production
    if (process.env.NODE_ENV === 'production') {
        startKeepAlive();
    }
});
