require('dotenv').config();
const express = require('express');
const path = require('path');
const admin = require('firebase-admin');
const axios = require('axios');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Validate critical environment variables
const requiredEnvVars = [
  'FIREBASE_PRIVATE_KEY',
  'FIREBASE_CLIENT_EMAIL', 
  'FIREBASE_DATABASE_URL',
  'PAYSTACK_SECRET_KEY',
  'HUBNET_API_KEY',
  'SESSION_SECRET',
  'BASE_URL'
];

requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
});

// Initialize Firebase Admin
// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'), // ✅ FIX: Convert \n to actual newlines
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
  console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
  console.error('❌ Firebase initialization failed:', error.message);
  process.exit(1);
}

// ====================
// PACKAGE CACHE SYSTEM
// ====================

let packageCache = {
    mtn: null,
    at: null,
    lastUpdated: null
};

function initializePackageCache() {
    console.log('🔄 Initializing real-time package cache...');
    
    admin.database().ref('packages/mtn').on('value', (snapshot) => {
        const packages = snapshot.val() || {};
        const packagesArray = Object.entries(packages).map(([key, pkg]) => ({
            id: key,
            ...pkg
        })).filter(pkg => pkg.active !== false);
        packageCache.mtn = packagesArray;
        packageCache.lastUpdated = Date.now();
        console.log('✅ MTN packages cache updated (' + packagesArray.length + ' packages)');
    });
    
    admin.database().ref('packages/at').on('value', (snapshot) => {
        const packages = snapshot.val() || {};
        const packagesArray = Object.entries(packages).map(([key, pkg]) => ({
            id: key,
            ...pkg
        })).filter(pkg => pkg.active !== false);
        packageCache.at = packagesArray;
        packageCache.lastUpdated = Date.now();
        console.log('✅ AirtelTigo packages cache updated (' + packagesArray.length + ' packages)');
    });
}

initializePackageCache();

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production', 
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.isAdmin) {
        next();
    } else {
        res.redirect('/admin-login');
    }
};

// ====================
// PAGE ROUTES
// ====================

app.get('/', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/purchase', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'purchase.html'));
});

app.get('/wallet', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'wallet.html'));
});

app.get('/orders', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'orders.html'));
});

app.get('/profile', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/admin-login', (req, res) => {
    if (req.session.user && req.session.user.isAdmin) return res.redirect('/admin');
    res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ====================
// AUTHENTICATION API ROUTES
// ====================

// User Registration
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password, firstName, lastName, phone } = req.body;
        
        const userRecord = await admin.auth().createUser({
            email,
            password,
            displayName: `${firstName} ${lastName}`,
            phoneNumber: phone
        });

        await admin.database().ref('users/' + userRecord.uid).set({
            firstName,
            lastName,
            email,
            phone,
            walletBalance: 0,
            createdAt: new Date().toISOString(),
            isAdmin: email === process.env.ADMIN_EMAIL
        });

        res.json({ 
            success: true, 
            userId: userRecord.uid,
            message: 'Account created successfully'
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(400).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
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
            }
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

        res.json({ 
            success: true, 
            message: 'Login successful',
            user: req.session.user
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(401).json({ 
            success: false, 
            error: error.response?.data?.error?.message || 'Invalid credentials' 
        });
    }
});

// Get current user
app.get('/api/user', requireAuth, (req, res) => {
    res.json({ 
        success: true, 
        user: req.session.user 
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Logout failed' });
        }
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

// ====================
// WALLET & PAYMENT ROUTES
// ====================

// Get wallet balance
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
            error: error.message 
        });
    }
});

// Get wallet transactions for a user
app.get('/api/wallet/transactions', requireAuth, async (req, res) => {
    try {
        const userId = req.session.user.uid;
        
        const transactionsSnapshot = await admin.database()
            .ref('transactions')
            .orderByChild('userId')
            .equalTo(userId)
            .once('value');
        
        const paymentsSnapshot = await admin.database()
            .ref('payments')
            .orderByChild('userId')
            .equalTo(userId)
            .once('value');

        const transactions = transactionsSnapshot.val() || {};
        const payments = paymentsSnapshot.val() || {};

        // Combine and format transactions
        let allTransactions = [];

        // Add data purchases (transactions)
        Object.entries(transactions).forEach(([id, transaction]) => {
            allTransactions.push({
                id,
                type: 'purchase',
                description: `${transaction.packageName} - ${transaction.network?.toUpperCase() || ''}`,
                amount: -transaction.amount, // Negative for purchases
                status: transaction.status || 'success',
                timestamp: transaction.timestamp,
                reference: transaction.reference
            });
        });

        // Add wallet funding (payments)
        Object.entries(payments).forEach(([id, payment]) => {
            allTransactions.push({
                id,
                type: 'funding',
                description: 'Wallet Funding',
                amount: payment.amount, // Positive for funding
                status: payment.status || 'success',
                timestamp: payment.timestamp,
                reference: payment.reference
            });
        });

        // Sort by timestamp (newest first)
        allTransactions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Limit to last 20 transactions
        allTransactions = allTransactions.slice(0, 20);

        res.json({
            success: true,
            transactions: allTransactions
        });
    } catch (error) {
        console.error('Error loading wallet transactions:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to load transactions'
        });
    }
});
// Paystack wallet funding - ABSORB 3% FEE
app.post('/api/initialize-payment', requireAuth, async (req, res) => {
    try {
        const { amount } = req.body;
        const userId = req.session.user.uid;
        const email = req.session.user.email;
        
        // Calculate Paystack amount (add 3% fee)
        const paystackAmount = Math.ceil(amount * 100 * 1.06); // Add 3% and convert to kobo
        
        console.log('💰 Payment calculation:', {
            userAmount: amount,
            paystackAmount: paystackAmount / 100,
            fee: (paystackAmount - (amount * 100)) / 100
        });

        const paystackResponse = await axios.post(
            `${process.env.PAYSTACK_BASE_URL}/transaction/initialize`,
            {
                email,
                amount: paystackAmount, // This includes our 3% fee
                callback_url: `${process.env.BASE_URL}/wallet?success=true`,
                metadata: {
                    userId: userId,
                    purpose: 'wallet_funding',
                    originalAmount: amount // Store original amount
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        res.json(paystackResponse.data);
    } catch (error) {
        console.error('Paystack initialization error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.response?.data?.message || error.message 
        });
    }
});

// Verify wallet payment - CREDIT ORIGINAL AMOUNT
app.get('/api/verify-payment/:reference', requireAuth, async (req, res) => {
    try {
        const { reference } = req.params;
        const userId = req.session.user.uid;
        
        const paystackResponse = await axios.get(
            `${process.env.PAYSTACK_BASE_URL}/transaction/verify/${reference}`,
            {
                headers: {
                    'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
                }
            }
        );

        const result = paystackResponse.data;
        
        if (result.data.status === 'success') {
            // Get the ORIGINAL amount from metadata (what user intended to add)
            const originalAmount = result.data.metadata.originalAmount || (result.data.amount / 100);
            const amount = parseFloat(originalAmount);
            
            console.log('✅ Payment verified:', {
                paidAmount: result.data.amount / 100,
                creditedAmount: amount,
                fee: (result.data.amount / 100) - amount
            });

            const userRef = admin.database().ref('users/' + userId);
            const userSnapshot = await userRef.once('value');
            const currentBalance = userSnapshot.val().walletBalance || 0;
            
            // Credit the ORIGINAL amount (without showing fee to user)
            await userRef.update({ 
                walletBalance: currentBalance + amount 
            });

            const paymentRef = admin.database().ref('payments').push();
            await paymentRef.set({
                userId,
                amount: amount, // Store original amount
                paystackAmount: result.data.amount / 100, // Store what Paystack actually charged
                fee: (result.data.amount / 100) - amount, // Store our absorbed fee
                reference,
                status: 'success',
                paystackData: result.data,
                timestamp: new Date().toISOString()
            });

            res.json({ 
                success: true, 
                amount: amount,
                newBalance: currentBalance + amount
            });
        } else {
            res.json({ 
                success: false, 
                error: 'Payment failed or pending' 
            });
        }
    } catch (error) {
        console.error('Payment verification error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.response?.data?.message || error.message 
        });
    }
});

// ====================
// DATA PURCHASE ROUTES - FIXED VOLUME CONVERSION
// ====================

// Get packages
app.get('/api/packages/:network', requireAuth, async (req, res) => {
    try {
        const { network } = req.params;
        
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
// ====================
// DOMAIN RESTRICTION MIDDLEWARE
// ====================

const allowedDomains = [
  'datasell.store',
  'datasell.com', 
  'datasell.onrender.com',
  'datasell.io',
  'datasell.pro',
  'datasell.shop',
  // Keep for local development
];

app.use((req, res, next) => {
  const host = req.get('host');
  const origin = req.get('origin');
  
  // Skip domain check for health endpoints (needed for UptimeRobot)
  if (req.path === '/api/health' || req.path === '/api/ping') {
    return next();
  }
  
  // Check if request comes from allowed domain
  const isAllowed = allowedDomains.some(domain => 
    host?.includes(domain) || origin?.includes(domain)
  );
  
  if (!isAllowed) {
    console.log('🚫 Blocked access from:', host, origin);
    return res.status(403).json({ 
      error: 'Access forbidden - Domain not allowed',
      allowedDomains: allowedDomains
    });
  }
  
  next();
});
// Add with other requires at top
const cors = require('cors');

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedDomains.some(domain => origin.includes(domain))) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
};

app.use(cors(corsOptions));
// Purchase with wallet - FIXED VOLUME
app.post('/api/purchase-data', requireAuth, async (req, res) => {
    try {
        const { network, volume, phoneNumber, amount, packageName } = req.body;
        const userId = req.session.user.uid;
        
        console.log('🔄 Purchase request received:', { network, volume, phoneNumber, amount, packageName });

        // ✅ FIXED: Convert volume from GB to MB for Hubtel
        let volumeValue = volume;
        if (volumeValue && parseInt(volumeValue) < 100) {
            volumeValue = (parseInt(volumeValue) * 1000).toString();
            console.log(`🔢 VOLUME CONVERTED: ${volume} → ${volumeValue}MB`);
        } else {
            console.log(`🔢 Volume already in MB: ${volumeValue}`);
        }

        console.log('📦 Final volume for Hubnet:', volumeValue);

        // Validation
        if (!/^\d{10}$/.test(phoneNumber)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Phone number must be 10 digits long' 
            });
        }

        const userRef = admin.database().ref('users/' + userId);
        const userSnapshot = await userRef.once('value');
        const userData = userSnapshot.val();
        
        if (!userData || userData.walletBalance < amount) {
            return res.status(400).json({ 
                success: false, 
                error: 'Insufficient wallet balance' 
            });
        }

        const reference = `DS-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Hubnet API call with CORRECT volume
        const hubnetResponse = await axios.post(
            `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`,
            {
                phone: phoneNumber,
                volume: volumeValue, // ✅ NOW CORRECT: "1000" instead of "1"
                reference: reference,
                referrer: userData.phone || '',
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
                volume: volumeValue,
                phoneNumber,
                amount,
                status: 'success',
                reference: reference,
                transactionId: hubnetData.transaction_id,
                hubnetResponse: hubnetData,
                timestamp: new Date().toISOString()
            });

            res.json({ 
                success: true, 
                data: hubnetData,
                newBalance: newBalance,
                message: 'Data purchase successful!'
            });
        } else {
            res.status(400).json({ 
                success: false, 
                error: hubnetData.reason || 'Purchase failed',
                hubnetCode: hubnetData.code
            });
        }
    } catch (error) {
        console.error('❌ Purchase error:', error);
        
        let errorMessage = error.message;
        if (error.response) {
            errorMessage = error.response.data?.reason || error.response.data?.message || error.message;
        }
        
        res.status(500).json({ 
            success: false, 
            error: errorMessage 
        });
    }
});
// ==================== SECURE FIREBASE CONFIG (CLIENT) ====================
app.get('/api/firebase-config', requireAuth, (req, res) => {
    try {
        console.log('🔧 Providing Firebase config to user:', req.session.user.email);
        
        const config = {
            apiKey: process.env.FIREBASE_API_KEY,
            authDomain: process.env.FIREBASE_AUTH_DOMAIN,
            databaseURL: process.env.FIREBASE_DATABASE_URL,
            projectId: process.env.FIREBASE_PROJECT_ID,
            storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
            messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
            appId: process.env.FIREBASE_APP_ID
        };

        // Validate that all required config values are present
        const missingConfigs = Object.entries(config)
            .filter(([key, value]) => !value)
            .map(([key]) => key);

        if (missingConfigs.length > 0) {
            console.error('❌ Missing Firebase config values:', missingConfigs);
            return res.status(500).json({ 
                success: false, 
                error: 'Firebase configuration incomplete' 
            });
        }

        console.log('✅ Firebase config provided successfully');
        res.json(config);
    } catch (error) {
        console.error('❌ Firebase config error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load Firebase configuration' 
        });
    }
});

// ==================== HUBNET WEBHOOK (LIVE DELIVERY UPDATE) ====================
const rateLimit = require('express-rate-limit');
const webhookLimiter = rateLimit({ windowMs: 60*1000, max: 5 });

app.post('/api/hubnet-webhook', webhookLimiter, async (req, res) => {
    console.log('Hubnet Webhook:', req.body);
    const { reference, status, code, reason, message, transaction_id } = req.body;

    if (!reference) return res.status(400).json({ error: 'Missing reference' });

    try {
        const snap = await admin.database()
            .ref('transactions')
            .orderByChild('reference')
            .equalTo(reference)
            .once('value');

        if (!snap.val()) return res.status(404).json({ error: 'Not found' });

        const [txId, tx] = Object.entries(snap.val())[0];
        if (tx.hubnetConfirmed) return res.json({ success: true, message: 'Already processed' });

        let update = { hubnetConfirmed: true, confirmedAt: new Date().toISOString() };

        if (status === true || code === '0000' || message?.toLowerCase().includes('delivered')) {
            update.status = 'delivered';
            update.hubnetStatus = 'delivered';
            update.reason = 'Package delivered';
        } else {
            update.status = 'failed';
            update.hubnetStatus = code || 'failed';
            update.reason = reason || message || 'Delivery failed';

            // Auto-refund
            if (tx.status === 'success') {
                const user = (await admin.database().ref(`users/${tx.userId}`).once('value')).val();
                await admin.database().ref(`users/${tx.userId}`).update({
                    walletBalance: (user.walletBalance || 0) + tx.amount
                });
                await admin.database().ref('refunds').push({
                    transactionId: txId,
                    userId: tx.userId,
                    amount: tx.amount,
                    reason: `Auto-refund: ${update.reason}`,
                    timestamp: new Date().toISOString()
                });
            }
        }

        await admin.database().ref(`transactions/${txId}`).update(update);
        res.json({ success: true });
    } catch (err) {
        console.error('Webhook error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});
// Initialize direct payment - ABSORB 3% FEE
app.post('/api/initialize-direct-payment', requireAuth, async (req, res) => {
    try {
        const { amount, phoneNumber, network, packageName } = req.body;
        const userId = req.session.user.uid;
        const email = req.session.user.email;

        console.log('💰 Direct payment calculation:', {
            packageAmount: amount,
            paystackAmount: Math.ceil(amount * 100 * 1.06) / 100,
            fee: (Math.ceil(amount * 100 * 1.06) - (amount * 100)) / 100
        });

        // Calculate Paystack amount (add 3% fee)
        const paystackAmount = Math.ceil(amount * 100 * 1.06);

        const paystackResponse = await axios.post(
            `${process.env.PAYSTACK_BASE_URL}/transaction/initialize`,
            {
                email,
                amount: paystackAmount, // Includes our 3% fee
                callback_url: `${process.env.BASE_URL}/verify-direct-payment`,
                metadata: {
                    userId: userId,
                    phoneNumber: phoneNumber,
                    network: network,
                    packageName: packageName,
                    originalAmount: amount, // Store original package price
                    purpose: 'direct_data_purchase'
                }
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const paystackData = paystackResponse.data;

        console.log('✅ Direct payment initialized:', {
            reference: paystackData.data.reference,
            userSees: amount,
            paystackCharges: paystackAmount / 100
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
        res.status(500).json({ 
            success: false, 
            error: error.response?.data?.message || error.message 
        });
    }
});

// Process direct purchase - USE ORIGINAL AMOUNT
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
                }
            }
        );

        const result = paystackResponse.data;

        if (result.data.status === 'success') {
            // Get the ORIGINAL amount from metadata
            const originalAmount = result.data.metadata.originalAmount;
            const { phoneNumber, network, packageName } = result.data.metadata;

            console.log('📦 Direct purchase details:', { 
                phoneNumber, network, packageName, 
                originalAmount, 
                paidAmount: result.data.amount / 100,
                absorbedFee: (result.data.amount / 100) - originalAmount
            });

            // ✅ FIXED: Convert volume from GB to MB for Hubtel
            let volume = '1000';
            if (packageName) {
                const volumeMatch = packageName.match(/\d+/);
                if (volumeMatch) {
                    const volumeNumber = parseInt(volumeMatch[0]);
                    volume = (volumeNumber * 1000).toString();
                    console.log(`🔢 DIRECT PURCHASE CONVERTED: ${volumeNumber}GB → ${volume}MB`);
                }
            }

            const hubnetResponse = await axios.post(
                `https://console.hubnet.app/live/api/context/business/transaction/${network}-new-transaction`,
                {
                    phone: phoneNumber,
                    volume: volume,
                  reference: reference,
                  referrer: userData.phone || '',
              
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
                    volume,
                    phoneNumber,
                    amount: originalAmount, // Store original amount
                    paystackAmount: result.data.amount / 100, // Store what was actually paid
                    fee: (result.data.amount / 100) - originalAmount, // Store absorbed fee
                    status: 'success',
                    reference: reference,
                    transactionId: hubnetData.transaction_id,
                    hubnetResponse: hubnetData,
                    paymentMethod: 'direct',
                    timestamp: new Date().toISOString()
                });

                res.json({ 
                    success: true, 
                    message: 'Data purchase successful!',
                    data: hubnetData
                });
            } else {
                console.error('❌ Hubnet purchase failed:', hubnetData);
                throw new Error(hubnetData.reason || `Hubnet error: ${hubnetData.code}`);
            }
        } else {
            throw new Error('Payment verification failed');
        }
    } catch (error) {
        console.error('❌ Direct purchase processing error:', error);
        
        let errorMessage = error.message;
        if (error.response) {
            errorMessage = error.response.data?.reason || error.response.data?.message || error.message;
        }
        
        res.status(500).json({ 
            success: false, 
            error: errorMessage,
            details: 'Failed to process data purchase after payment'
        });
    }
});
// Hubnet balance check
app.get('/api/hubnet-balance', requireAuth, async (req, res) => {
    try {
        const response = await axios.get(
            'https://console.hubnet.app/live/api/context/business/transaction/check_balance',
            {
                headers: {
                    'token': `Bearer ${process.env.HUBNET_API_KEY}`,
                    'Content-Type': 'application/json'
                }
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
            error: error.message 
        });
    }
});
// ====================
// KEEP ALIVE ENDPOINTS
// ====================

// Simple health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        server: 'DataSell API',
        uptime: process.uptime()
    });
});

// Lightweight ping endpoint
app.get('/api/ping', (req, res) => {
    res.json({ 
        message: 'pong', 
        timestamp: Date.now()
    });
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
            totalSpent: ordersArray.reduce((total, order) => total + (order.amount || 0), 0)
        };

        res.json({ 
            success: true, 
            stats: stats 
        });
    } catch (error) {
        console.error('Profile stats error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
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
            error: error.message 
        });
    }
});

// ====================
// COMPREHENSIVE ADMIN API ENDPOINTS
// ====================

// 1. DASHBOARD ANALYTICS
app.get('/api/admin/dashboard/stats', requireAdmin, async (req, res) => {
    try {
        const [usersSnapshot, transactionsSnapshot, paymentsSnapshot, packagesSnapshot] = await Promise.all([
            admin.database().ref('users').once('value'),
            admin.database().ref('transactions').once('value'),
            admin.database().ref('payments').once('value'),
            admin.database().ref('packages').once('value')
        ]);

        const users = usersSnapshot.val() || {};
        const transactions = transactionsSnapshot.val() || {};
        const payments = paymentsSnapshot.val() || {};
        const packages = packagesSnapshot.val() || {};

        const usersArray = Object.values(users);
        const transactionsArray = Object.values(transactions);
        const paymentsArray = Object.values(payments);

        // Calculate time-based metrics
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
        const monthAgo = new Date(today.getFullYear(), today.getMonth() - 1, today.getDate());

        const todayTransactions = transactionsArray.filter(t => 
            new Date(t.timestamp) >= today
        );
        const weekTransactions = transactionsArray.filter(t => 
            new Date(t.timestamp) >= weekAgo
        );
        const monthTransactions = transactionsArray.filter(t => 
            new Date(t.timestamp) >= monthAgo
        );

        // Calculate revenue
        const totalRevenue = paymentsArray.reduce((sum, payment) => sum + (payment.amount || 0), 0);
        const todayRevenue = todayTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);
        const weekRevenue = weekTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);
        const monthRevenue = monthTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);

        // Top packages
        const packageSales = {};
        transactionsArray.forEach(t => {
            if (t.packageName) {
                packageSales[t.packageName] = (packageSales[t.packageName] || 0) + 1;
            }
        });

        const topPackages = Object.entries(packageSales)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([name, count]) => ({ name, count }));

        // Network performance
        const networkStats = {
            mtn: transactionsArray.filter(t => t.network === 'mtn').length,
            at: transactionsArray.filter(t => t.network === 'at').length
        };

        const stats = {
            // Basic stats
            totalUsers: usersArray.length,
            totalTransactions: transactionsArray.length,
            totalRevenue,
            successfulTransactions: transactionsArray.filter(t => t.status === 'success').length,
            
            // Time-based stats
            todayTransactions: todayTransactions.length,
            todayRevenue,
            weekRevenue,
            monthRevenue,
            
            // User growth (last 30 days)
            newUsers: usersArray.filter(u => 
                new Date(u.createdAt) >= monthAgo
            ).length,
            
            // Package stats
            topPackages,
            networkStats,
            
            // Performance metrics
            successRate: transactionsArray.length > 0 ? 
                (transactionsArray.filter(t => t.status === 'success').length / transactionsArray.length * 100).toFixed(1) : 0
        };

        res.json({ success: true, stats });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 2. USER MANAGEMENT
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const usersSnapshot = await admin.database().ref('users').once('value');
        const transactionsSnapshot = await admin.database().ref('transactions').once('value');
        
        const users = usersSnapshot.val() || {};
        const transactions = transactionsSnapshot.val() || {};

        const usersArray = Object.entries(users).map(([uid, userData]) => {
            const userTransactions = Object.values(transactions).filter(t => t.userId === uid);
            const totalSpent = userTransactions.reduce((sum, t) => sum + (t.amount || 0), 0);
            
            return {
                uid,
                ...userData,
                totalSpent,
                transactionCount: userTransactions.length,
                lastActivity: userData.lastLogin || userData.createdAt,
                status: userData.suspended ? 'suspended' : 'active'
            };
        });

        res.json({ success: true, users: usersArray });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});
// ====================
// USER ROLE MANAGEMENT
// ====================

// Update user role (from regular to vip/premium)
app.post('/api/admin/users/:uid/update-role', requireAdmin, async (req, res) => {
    try {
        const { uid } = req.params;
        const { role } = req.body;

        console.log('🔄 Updating user role:', { uid, role });

        if (!['regular', 'vip', 'premium'].includes(role)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid role. Must be: regular, vip, or premium' 
            });
        }

        const userRef = admin.database().ref('users/' + uid);
        const userSnapshot = await userRef.once('value'); // ✅ FIXED: userRef instead of userSnapshot
        
        if (!userSnapshot.exists()) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const userData = userSnapshot.val();
        const currentRole = userData.pricingGroup || 'regular';
        
        await userRef.update({ 
            pricingGroup: role,
            roleUpdatedAt: new Date().toISOString(),
            previousRole: currentRole
        });

        // Log admin action
        const logRef = admin.database().ref('adminLogs').push();
        await logRef.set({
            adminId: req.session.user.uid,
            action: 'update_user_role',
            targetUserId: uid,
            details: `Changed user role from ${currentRole} to ${role}`,
            timestamp: new Date().toISOString(),
            ip: req.ip
        });

        console.log('✅ User role updated successfully:', { uid, from: currentRole, to: role });

        res.json({ 
            success: true, 
            message: `User role updated from ${currentRole} to ${role} successfully`,
            previousRole: currentRole,
            newRole: role
        });
    } catch (error) {
        console.error('❌ Update user role error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Bulk update user roles
app.post('/api/admin/users/bulk-update-roles', requireAdmin, async (req, res) => {
    try {
        const { userIds, role } = req.body;

        console.log('🔄 Bulk updating user roles:', { userIds, role });

        if (!['regular', 'vip', 'premium'].includes(role)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid role' 
            });
        }

        if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'User IDs array is required' 
            });
        }

        const updates = {};
        const timestamp = new Date().toISOString();

        // Verify all users exist and prepare updates
        for (const uid of userIds) {
            const userSnapshot = await admin.database().ref('users/' + uid).once('value');
            if (userSnapshot.exists()) {
                updates[`users/${uid}/pricingGroup`] = role;
                updates[`users/${uid}/roleUpdatedAt`] = timestamp;
            }
        }

        // Apply all updates
        await admin.database().ref().update(updates);

        // Log bulk action
        const logRef = admin.database().ref('adminLogs').push();
        await logRef.set({
            adminId: req.session.user.uid,
            action: 'bulk_update_user_roles',
            targetUserIds: userIds,
            details: `Bulk updated ${userIds.length} users to ${role} role`,
            timestamp: timestamp,
            ip: req.ip
        });

        console.log('✅ Bulk role update successful:', { count: userIds.length, role });

        res.json({ 
            success: true, 
            message: `Updated ${userIds.length} users to ${role} role successfully` 
        });
    } catch (error) {
        console.error('❌ Bulk update user roles error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});
// Toggle user suspension
app.post('/api/admin/users/:uid/toggle-suspend', requireAdmin, async (req, res) => {
    try {
        const { uid } = req.params;
        const userRef = admin.database().ref('users/' + uid);
        const userSnapshot = await userRef.once('value');
        
        if (!userSnapshot.exists()) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const currentStatus = userSnapshot.val().suspended || false;
        await userRef.update({ suspended: !currentStatus });

        res.json({ 
            success: true, 
            message: `User ${!currentStatus ? 'suspended' : 'activated'} successfully`,
            suspended: !currentStatus
        });
    } catch (error) {
        console.error('Toggle suspend error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add funds to user wallet
app.post('/api/admin/users/:uid/add-funds', requireAdmin, async (req, res) => {
    try {
        const { uid } = req.params;
        const { amount, note } = req.body;

        if (!amount || amount <= 0) {
            return res.status(400).json({ success: false, error: 'Invalid amount' });
        }

        const userRef = admin.database().ref('users/' + uid);
        const userSnapshot = await userRef.once('value');
        
        if (!userSnapshot.exists()) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const currentBalance = userSnapshot.val().walletBalance || 0;
        const newBalance = currentBalance + parseFloat(amount);

        await userRef.update({ walletBalance: newBalance });

        // Record the manual fund addition
        const fundRef = admin.database().ref('manualFunds').push();
        await fundRef.set({
            userId: uid,
            adminId: req.session.user.uid,
            amount: parseFloat(amount),
            note: note || 'Manual fund addition by admin',
            previousBalance: currentBalance,
            newBalance: newBalance,
            timestamp: new Date().toISOString()
        });

        // Log admin action
        const logRef = admin.database().ref('adminLogs').push();
        await logRef.set({
            adminId: req.session.user.uid,
            action: 'add_funds',
            targetUserId: uid,
            details: `Added ₵${amount} to user wallet`,
            timestamp: new Date().toISOString(),
            ip: req.ip
        });

        res.json({ 
            success: true, 
            message: `₵${amount} added successfully`,
            newBalance: newBalance
        });
    } catch (error) {
        console.error('Add funds error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 3. PACKAGE MANAGEMENT
app.get('/api/admin/packages', requireAdmin, async (req, res) => {
    try {
        // If cache is empty, load from database
        if (!packageCache.mtn || !packageCache.at) {
            console.log('📦 Loading packages into admin cache...');
            const packagesSnapshot = await admin.database().ref('packages').once('value');
            const packages = packagesSnapshot.val() || {};
            
            packageCache.mtn = Object.entries(packages.mtn || {}).map(([key, pkg]) => ({
                id: key,
                ...pkg
            }));
            
            packageCache.at = Object.entries(packages.at || {}).map(([key, pkg]) => ({
                id: key,
                ...pkg
            }));
        }
        
        res.json({ 
            success: true, 
            packages: {
                mtn: packageCache.mtn,
                at: packageCache.at
            }
        });
    } catch (error) {
        console.error('Admin packages error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update package price
app.post('/api/admin/packages/update-price', requireAdmin, async (req, res) => {
    try {
        const { network, packageId, newPrice } = req.body;
        
        console.log('🔄 Updating package:', { network, packageId, newPrice });

        // Get ALL packages to search through them
        const packagesRef = admin.database().ref(`packages/${network}`);
        const packagesSnapshot = await packagesRef.once('value');
        const packages = packagesSnapshot.val() || {};
        
        console.log('📦 Available packages in Firebase:', Object.keys(packages));

        // Convert frontend ID to match your Firebase keys
        let packageKey = packageId;
        
        // Remove "mtn-" or "at-" prefix
        if (packageId.startsWith('mtn-')) {
            packageKey = packageId.replace('mtn-', '');
        } else if (packageId.startsWith('at-')) {
            packageKey = packageId.replace('at-', '');
        }
        
        // Convert number to match your keys
        const keyMap = {
            '1000': '1gb',
            '2000': '2', 
            '3000': '3',
            '4000': '4',
            '5000': '5',
            '6000': '6',
            '7000': '7',
            '8000': '8',
            '9000': '9',
            '10000': '10',
            '20000': '20',
            '30000': '30',
            '40000': '40',
            '50000': '50',
            '60000': '60',
            '70000': '70',
            '80000': '80',
            '90000': '90',
            '100000': '100gb'
        };
        
        if (keyMap[packageKey]) {
            packageKey = keyMap[packageKey];
        }
        
        console.log('🔍 Searching for package key:', packageKey);

        // Check if package exists
        if (!packages[packageKey]) {
            return res.status(404).json({ 
                success: false, 
                error: `Package "${packageId}" not found. Tried key: "${packageKey}". Available: ${Object.keys(packages).join(', ')}` 
            });
        }

        console.log('✅ Found package:', packages[packageKey]);

        // Update the price
        await admin.database().ref(`packages/${network}/${packageKey}`).update({
            price: parseFloat(newPrice)
        });

        res.json({ 
            success: true, 
            message: `"${packages[packageKey].name}" price updated to ₵${newPrice}` 
        });
    } catch (error) {
        console.error('Update package error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Bulk update package prices
app.post('/api/admin/packages/bulk-update', requireAdmin, async (req, res) => {
    try {
        const { network, percentageChange, fixedChange, operation } = req.body;
        const packagesRef = admin.database().ref(`packages/${network}`);
        const packagesSnapshot = await packagesRef.once('value');
        const packages = packagesSnapshot.val();

        const updates = {};
        
        Object.keys(packages).forEach(packageId => {
            const package = packages[packageId];
            let newPrice = package.price;
            
            if (operation === 'percentage' && percentageChange) {
                newPrice = package.price * (1 + percentageChange / 100);
            } else if (operation === 'fixed' && fixedChange) {
                newPrice = package.price + parseFloat(fixedChange);
            }
            
            // Ensure price doesn't go below 0
            newPrice = Math.max(0.1, newPrice);
            
            updates[`${network}/${packageId}/price`] = parseFloat(newPrice.toFixed(2));
        });

        await admin.database().ref('packages').update(updates);

        res.json({ 
            success: true, 
            message: `Bulk price update completed for ${network}` 
        });
    } catch (error) {
        console.error('Bulk update error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Toggle package active status
app.post('/api/admin/packages/toggle-active', requireAdmin, async (req, res) => {
    try {
        const { network, packageId } = req.body;
        const packageRef = admin.database().ref(`packages/${network}/${packageId}`);
        const packageSnapshot = await packageRef.once('value');
        
        if (!packageSnapshot.exists()) {
            return res.status(404).json({ success: false, error: 'Package not found' });
        }

        const currentStatus = packageSnapshot.val().active !== false;
        await packageRef.update({ active: !currentStatus });

        res.json({ 
            success: true, 
            message: `Package ${!currentStatus ? 'activated' : 'deactivated'}`,
            active: !currentStatus
        });
    } catch (error) {
        console.error('Toggle package error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Create new package
app.post('/api/admin/packages/create', requireAdmin, async (req, res) => {
    try {
        const { network, name, volume, price, validity } = req.body;
        const packageId = `${network}-${volume}`;
        
        const newPackage = {
            id: packageId,
            name,
            volume,
            price: parseFloat(price),
            validity: validity || '30 days',
            active: true
        };

        await admin.database().ref(`packages/${network}/${packageId}`).set(newPackage);

        res.json({ 
            success: true, 
            message: 'Package created successfully',
            package: newPackage
        });
    } catch (error) {
        console.error('Create package error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete package
app.delete('/api/admin/packages/:network/:packageId', requireAdmin, async (req, res) => {
    try {
        const { network, packageId } = req.params;
        
        await admin.database().ref(`packages/${network}/${packageId}`).remove();

        res.json({ 
            success: true, 
            message: 'Package deleted successfully'
        });
    } catch (error) {
        console.error('Delete package error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// RESTORE PACKAGES - NON-EXPIRY
app.post('/api/admin/packages/restore-all', requireAdmin, async (req, res) => {
    try {
        const allPackages = {
            mtn: {
                // MTN Data Packages - NON-EXPIRY
                '1gb': { name: '1GB', price: 5.00, validity: 'Non-Expiry', active: true },
                '2': { name: '2GB', price: 8.00, validity: 'Non-Expiry', active: true },
                '3': { name: '3GB', price: 10.00, validity: 'Non-Expiry', active: true },
                '4': { name: '4GB', price: 12.00, validity: 'Non-Expiry', active: true },
                '5': { name: '5GB', price: 15.00, validity: 'Non-Expiry', active: true },
                '6': { name: '6GB', price: 18.00, validity: 'Non-Expiry', active: true },
                '7': { name: '7GB', price: 20.00, validity: 'Non-Expiry', active: true },
                '8': { name: '8GB', price: 22.00, validity: 'Non-Expiry', active: true },
                '9': { name: '9GB', price: 25.00, validity: 'Non-Expiry', active: true },
                '10': { name: '10GB', price: 28.00, validity: 'Non-Expiry', active: true },
                '20': { name: '20GB', price: 35.00, validity: 'Non-Expiry', active: true },
                '30': { name: '30GB', price: 45.00, validity: 'Non-Expiry', active: true },
                '40': { name: '40GB', price: 55.00, validity: 'Non-Expiry', active: true },
                '50': { name: '50GB', price: 65.00, validity: 'Non-Expiry', active: true },
                '60': { name: '60GB', price: 75.00, validity: 'Non-Expiry', active: true },
                '70': { name: '70GB', price: 85.00, validity: 'Non-Expiry', active: true },
                '80': { name: '80GB', price: 95.00, validity: 'Non-Expiry', active: true },
                '90': { name: '90GB', price: 105.00, validity: 'Non-Expiry', active: true },
                '100gb': { name: '100GB', price: 115.00, validity: 'Non-Expiry', active: true }
            },
            at: {
                // AirtelTigo Data Packages - NON-EXPIRY
                '1gb': { name: '1GB', price: 5.00, validity: 'Non-Expiry', active: true },
                '2': { name: '2GB', price: 8.00, validity: 'Non-Expiry', active: true },
                '3': { name: '3GB', price: 10.00, validity: 'Non-Expiry', active: true },
                '4': { name: '4GB', price: 12.00, validity: 'Non-Expiry', active: true },
                '5': { name: '5GB', price: 15.00, validity: 'Non-Expiry', active: true },
                '6': { name: '6GB', price: 18.00, validity: 'Non-Expiry', active: true },
                '7': { name: '7GB', price: 20.00, validity: 'Non-Expiry', active: true },
                '8': { name: '8GB', price: 22.00, validity: 'Non-Expiry', active: true },
                '9': { name: '9GB', price: 25.00, validity: 'Non-Expiry', active: true },
                '10': { name: '10GB', price: 28.00, validity: 'Non-Expiry', active: true },
                '20': { name: '20GB', price: 35.00, validity: 'Non-Expiry', active: true },
                '30': { name: '30GB', price: 45.00, validity: 'Non-Expiry', active: true },
                '40': { name: '40GB', price: 55.00, validity: 'Non-Expiry', active: true },
                '50': { name: '50GB', price: 65.00, validity: 'Non-Expiry', active: true },
                '60': { name: '60GB', price: 75.00, validity: 'Non-Expiry', active: true },
                '70': { name: '70GB', price: 85.00, validity: 'Non-Expiry', active: true },
                '80': { name: '80GB', price: 95.00, validity: 'Non-Expiry', active: true },
                '90': { name: '90GB', price: 105.00, validity: 'Non-Expiry', active: true },
                '100gb': { name: '100GB', price: 115.00, validity: 'Non-Expiry', active: true }
            }
        };

        // Save all packages to Firebase
        await admin.database().ref('packages').set(allPackages);

        res.json({ 
            success: true, 
            message: 'All packages restored successfully with Non-Expiry validity!' 
        });
    } catch (error) {
        console.error('Restore packages error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Debug package structure
app.get('/api/admin/debug-packages', requireAdmin, async (req, res) => {
    try {
        const packagesSnapshot = await admin.database().ref('packages').once('value');
        const packages = packagesSnapshot.val() || {};
        
        res.json({ 
            success: true, 
            packages: packages 
        });
    } catch (error) {
        console.error('Debug packages error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 4. ORDER MANAGEMENT
app.get('/api/admin/transactions', requireAdmin, async (req, res) => {
    try {
        const { status, network, dateFrom, dateTo, search, limit } = req.query;
        
        const transactionsSnapshot = await admin.database().ref('transactions').once('value');
        const usersSnapshot = await admin.database().ref('users').once('value');
        
        let transactions = Object.entries(transactionsSnapshot.val() || {}).map(([id, transaction]) => ({
            id,
            ...transaction
        }));

        const users = usersSnapshot.val() || {};

        // Apply filters
        let filteredTransactions = transactions;

        if (status && status !== 'all') {
            filteredTransactions = filteredTransactions.filter(t => t.status === status);
        }
        
        if (network && network !== 'all') {
            filteredTransactions = filteredTransactions.filter(t => t.network === network);
        }
        
        if (dateFrom) {
            filteredTransactions = filteredTransactions.filter(t => 
                new Date(t.timestamp) >= new Date(dateFrom)
            );
        }
        
        if (dateTo) {
            const endDate = new Date(dateTo);
            endDate.setHours(23, 59, 59, 999);
            filteredTransactions = filteredTransactions.filter(t => 
                new Date(t.timestamp) <= endDate
            );
        }
        
        if (search) {
            filteredTransactions = filteredTransactions.filter(t => 
                t.phoneNumber?.includes(search) ||
                t.reference?.includes(search) ||
                t.packageName?.toLowerCase().includes(search.toLowerCase())
            );
        }

        // Apply limit if specified
        if (limit) {
            filteredTransactions = filteredTransactions.slice(0, parseInt(limit));
        }

        // Add user information to transactions
        const transactionsWithUsers = filteredTransactions.map(transaction => {
            const user = users[transaction.userId];
            return {
                ...transaction,
                userName: user ? `${user.firstName} ${user.lastName}` : 'Unknown User',
                userEmail: user?.email || 'N/A'
            };
        });

        // Sort by timestamp (newest first)
        transactionsWithUsers.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        res.json({ success: true, transactions: transactionsWithUsers });
    } catch (error) {
        console.error('Admin transactions error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Process refund
app.post('/api/admin/transactions/:id/refund', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        
        const transactionRef = admin.database().ref('transactions/' + id);
        const transactionSnapshot = await transactionRef.once('value');
        
        if (!transactionSnapshot.exists()) {
            return res.status(404).json({ success: false, error: 'Transaction not found' });
        }

        const transaction = transactionSnapshot.val();
        
        // Refund to user wallet
        const userRef = admin.database().ref('users/' + transaction.userId);
        const userSnapshot = await userRef.once('value');
        const userData = userSnapshot.val();
        
        const newBalance = (userData.walletBalance || 0) + transaction.amount;
        await userRef.update({ walletBalance: newBalance });

        // Update transaction status
        await transactionRef.update({ 
            status: 'refunded',
            refundReason: reason,
            refundedAt: new Date().toISOString()
        });

        // Record refund
        const refundRef = admin.database().ref('refunds').push();
        await refundRef.set({
            transactionId: id,
            userId: transaction.userId,
            amount: transaction.amount,
            reason,
            processedBy: req.session.user.uid,
            processedAt: new Date().toISOString()
        });

        res.json({ 
            success: true, 
            message: `₵${transaction.amount} refunded to user wallet`,
            newBalance: newBalance
        });
    } catch (error) {
        console.error('Refund error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 5. PRICING CONTROL
app.get('/api/admin/pricing/groups', requireAdmin, async (req, res) => {
    try {
        const pricingSnapshot = await admin.database().ref('pricingGroups').once('value');
        const pricing = pricingSnapshot.val() || {
            regular: { discount: 0, name: 'Regular Users' },
            vip: { discount: 10, name: 'VIP Users' },
            premium: { discount: 15, name: 'Premium Users' }
        };

        res.json({ success: true, pricingGroups: pricing });
    } catch (error) {
        console.error('Pricing groups error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/admin/pricing/groups/update', requireAdmin, async (req, res) => {
    try {
        const { group, discount, name } = req.body;
        
        // Use default names if name is not provided
        const groupNames = {
            regular: 'Regular Users',
            vip: 'VIP Users', 
            premium: 'Premium Users'
        };
        
        await admin.database().ref(`pricingGroups/${group}`).set({
            discount: parseFloat(discount),
            name: name || groupNames[group] || group
        });

        res.json({ 
            success: true, 
            message: `Pricing group ${group} updated successfully` 
        });
    } catch (error) {
        console.error('Update pricing group error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 6. REVENUE REPORTS
app.get('/api/admin/reports/sales', requireAdmin, async (req, res) => {
    try {
        const { period } = req.query; // daily, weekly, monthly, yearly
        
        const transactionsSnapshot = await admin.database().ref('transactions').once('value');
        const paymentsSnapshot = await admin.database().ref('payments').once('value');
        
        const transactions = Object.values(transactionsSnapshot.val() || {});
        const payments = Object.values(paymentsSnapshot.val() || {});

        const now = new Date();
        let startDate;

        switch (period) {
            case 'daily':
                startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                break;
            case 'weekly':
                startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                break;
            case 'monthly':
                startDate = new Date(now.getFullYear(), now.getMonth(), 1);
                break;
            case 'yearly':
                startDate = new Date(now.getFullYear(), 0, 1);
                break;
            default:
                startDate = new Date(0); // All time
        }

        const filteredTransactions = transactions.filter(t => 
            new Date(t.timestamp) >= startDate
        );
        const filteredPayments = payments.filter(p => 
            new Date(p.timestamp) >= startDate
        );

        const report = {
            period,
            totalSales: filteredTransactions.reduce((sum, t) => sum + (t.amount || 0), 0),
            totalRevenue: filteredPayments.reduce((sum, p) => sum + (p.amount || 0), 0),
            successfulTransactions: filteredTransactions.filter(t => t.status === 'success').length,
            failedTransactions: filteredTransactions.filter(t => t.status === 'failed').length,
            totalTransactions: filteredTransactions.length,
            averageOrderValue: filteredTransactions.length > 0 ? 
                filteredTransactions.reduce((sum, t) => sum + (t.amount || 0), 0) / filteredTransactions.length : 0
        };

        res.json({ success: true, report });
    } catch (error) {
        console.error('Sales report error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 7. SYSTEM MONITORING
app.get('/api/admin/system/status', requireAdmin, async (req, res) => {
    try {
        // Check Hubnet balance
        let hubnetStatus = { status: 'unknown', balance: 0 };
        try {
            const hubnetResponse = await axios.get(
                'https://console.hubnet.app/live/api/context/business/transaction/check_balance',
                {
                    headers: {
                        'token': `Bearer ${process.env.HUBNET_API_KEY}`,
                        'Content-Type': 'application/json'
                    },
                    timeout: 10000
                }
            );
            hubnetStatus = { status: 'online', balance: hubnetResponse.data };
        } catch (error) {
            hubnetStatus = { status: 'offline', error: error.message };
        }

        // Check Paystack status (simplified check)
        let paystackStatus = { status: 'unknown' };
        try {
            await axios.get(
                `${process.env.PAYSTACK_BASE_URL}/bank`,
                {
                    headers: {
                        'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
                    },
                    timeout: 10000
                }
            );
            paystackStatus = { status: 'online' };
        } catch (error) {
            paystackStatus = { status: 'offline', error: error.message };
        }

        // Get system metrics
        const transactionsSnapshot = await admin.database().ref('transactions').once('value');
        const transactions = Object.values(transactionsSnapshot.val() || {});
        
        const recentTransactions = transactions.filter(t => 
            new Date(t.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
        );

        const successRate = recentTransactions.length > 0 ? 
            (recentTransactions.filter(t => t.status === 'success').length / recentTransactions.length * 100).toFixed(1) : 100;

        const systemStatus = {
            hubnet: hubnetStatus,
            paystack: paystackStatus,
            firebase: { status: 'online' }, // If we got here, Firebase is working
            server: { status: 'healthy' },
            successRate: parseFloat(successRate),
            recentTransactions: recentTransactions.length
        };

        res.json({ success: true, systemStatus });
    } catch (error) {
        console.error('System status error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Hubnet balance check for admin panel
app.get('/api/admin/system/hubnet-balance', requireAdmin, async (req, res) => {
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
        res.json({ success: true, balance: response.data });
    } catch (error) {
        console.error('Hubnet balance error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 8. NOTIFICATION SYSTEM
app.post('/api/admin/notifications/send', requireAdmin, async (req, res) => {
    try {
        const { title, message, type, targetUsers } = req.body; // targetUsers: 'all', 'vip', 'specific'
        
        const notificationRef = admin.database().ref('notifications').push();
        await notificationRef.set({
            title,
            message,
            type,
            targetUsers,
            sentBy: req.session.user.uid,
            sentAt: new Date().toISOString(),
            status: 'sent'
        });

        res.json({ 
            success: true, 
            message: 'Notification sent successfully' 
        });
    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});
// ==================== ADMIN: SECURE FIREBASE CONFIG ====================
app.get('/api/admin/firebase-config', requireAdmin, (req, res) => {
  res.json({
    apiKey: process.env.FIREBASE_API_KEY,
    authDomain: process.env.FIREBASE_AUTH_DOMAIN,
    databaseURL: process.env.FIREBASE_DATABASE_URL,
    projectId: process.env.FIREBASE_PROJECT_ID,
  });
});

// ==================== ADMIN: HUBNET BALANCE ====================
app.get('/api/admin/hubnet-balance', requireAdmin, async (req, res) => {
  try {
    const response = await axios.get('https://console.hubnet.app/live/api/context/business/transaction/check_balance', {
      headers: { 'token': `Bearer ${process.env.HUBNET_API_KEY}`, 'Content-Type': 'application/json' }
    });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Balance check failed' });
  }
});

// ==================== ADMIN: RESEND ORDER ====================
app.post('/api/admin/transactions/:id/resend', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const txSnapshot = await admin.database().ref('transactions/' + id).once('value');
  const tx = txSnapshot.val();
  if (!tx || tx.status !== 'failed') return res.status(400).json({ error: 'Invalid order' });

  const hubnetRes = await axios.post(
    `https://console.hubnet.app/live/api/context/business/transaction/${tx.network}-new-transaction`,
    {
      phone: tx.phoneNumber,
      volume: tx.volume,
      reference: `RESEND-${tx.reference}-${Date.now()}`,
      webhook: `${process.env.BASE_URL}/api/hubnet-webhook`
    },
    { headers: { 'token': `Bearer ${process.env.HUBNET_API_KEY}`, 'Content-Type': 'application/json' } }
  );

  if (hubnetRes.data.code === '0000') {
    await admin.database().ref('transactions/' + id).update({ status: 'processing', resendAttempt: (tx.resendAttempt || 0) + 1 });
    res.json({ success: true, message: 'Resend initiated' });
  } else {
    res.status(400).json({ error: hubnetRes.data.reason });
  }
});

// ==================== ADMIN: EXPORT ORDERS CSV ====================
app.get('/api/admin/export-orders', requireAdmin, async (req, res) => {
  const snapshot = await admin.database().ref('transactions').once('value');
  const txs = Object.entries(snapshot.val() || {}).map(([id, t]) => ({ id, ...t }));
  const csv = ['ID,User,Network,Package,Phone,Amount,Status,Reference,Date\n', ...txs.map(t => `"${t.id}","${t.userName}","${t.network}","${t.packageName}","${t.phoneNumber}",${t.amount},"${t.status}","${t.reference}","${t.timestamp}"`).join('\n')];
  res.header('Content-Type', 'text/csv');
  res.attachment('orders.csv');
  res.send(csv);
});
// 9. SECURITY & ACCESS CONTROL
app.get('/api/admin/security/logs', requireAdmin, async (req, res) => {
    try {
        const logsSnapshot = await admin.database().ref('adminLogs').once('value');
        const logs = Object.entries(logsSnapshot.val() || {}).map(([id, log]) => ({
            id,
            ...log
        })).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        res.json({ success: true, logs });
    } catch (error) {
        console.error('Security logs error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 10. INTEGRATION MANAGEMENT
app.get('/api/admin/integrations', requireAdmin, async (req, res) => {
    try {
        const integrations = {
            hubnet: {
                apiKey: process.env.HUBNET_API_KEY ? '••••••••' + process.env.HUBNET_API_KEY.slice(-4) : 'Not set',
                baseUrl: 'https://console.hubnet.app/live/api'
            },
            paystack: {
                secretKey: process.env.PAYSTACK_SECRET_KEY ? '••••••••' + process.env.PAYSTACK_SECRET_KEY.slice(-4) : 'Not set',
                publicKey: process.env.PAYSTACK_PUBLIC_KEY ? '••••••••' + process.env.PAYSTACK_PUBLIC_KEY.slice(-4) : 'Not set',
                baseUrl: process.env.PAYSTACK_BASE_URL
            },
            firebase: {
                projectId: process.env.FIREBASE_PROJECT_ID,
                databaseUrl: process.env.FIREBASE_DATABASE_URL
            }
        };

        res.json({ success: true, integrations });
    } catch (error) {
        console.error('Integrations error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ====================
// HEALTH & ERROR HANDLING
// ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV,
        firebase: process.env.FIREBASE_PROJECT_ID ? 'Configured' : 'Missing',
        paystack: process.env.PAYSTACK_SECRET_KEY ? 'Configured' : 'Missing',
        hubnet: process.env.HUBNET_API_KEY ? 'Configured' : 'Missing'
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Endpoint not found' 
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 DataSell server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV}`);
    console.log(`🌐 Base URL: ${process.env.BASE_URL}`);
    console.log(`🔥 Firebase Project: ${process.env.FIREBASE_PROJECT_ID}`);
    console.log(`📡 Hubnet API: Integrated`);
    console.log(`💳 Paystack: Live Mode`);
    console.log(`👑 Admin Panel: Ready at /admin`);
    console.log(`🛒 Purchase System: Volume conversion FIXED`);
});