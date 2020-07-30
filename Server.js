// Load Express and other dependencies
var express = require("express"),
    http = require("http"),
    request = require("request"),
    bodyParser = require("body-parser"),
    morgan = require("morgan"),
    app = express(),
    path = require("path"),
    https = require("https"),
    fs = require("fs"),
    base64url = require("base64-url"),
    nJwt = require("njwt"),
    CryptoJS = require("crypto-js"),
    crypto = require("crypto"),
    apiVersion = "v45.0",
    clientId = process.env.CLIENT_ID,
    clientSecret = process.env.CLIENT_SECRET,
    callbackURL = process.env.CALLBACK_URL,
    baseURL = process.env.BASE_URL,
    username = process.env.USERNAME,
    jwt_aud = "https://login.salesforce.com",
    endpointUrl = "",
    state = "",
    refreshToken = "",
    webserverType = "";

// Set default view engine to ejs. This will be used when calling res.render()
app.set("view engine", "ejs");

// Let Express know where the client files are located
app.use(express.static(__dirname + "/client"));

// Setting up of app
app.use(morgan("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Set the port to use based on the environment variables
app.set("port", process.env.PORT);

/**
 * Extract Access token from POST response and redirect to page queryresult
 */
function accessTokenCallback(err, remoteResponse, remoteBody, res) {
    // Display error if error is returned to callback function
    if (err) {
        return res.status(500).end("Error");
    }

    console.log("Access token response:" + remoteBody);

    // Retrieve the response
    var sfdcResponse = JSON.parse(remoteBody);
    var identityUrl = sfdcResponse.id;
    var issuedAt = sfdcResponse.issued_at;

    // Check the signature
    if (identityUrl && issuedAt) {
        var hash = CryptoJS.HmacSHA256(identityUrl + issuedAt, clientSecret);
        var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);
        if (hashInBase64 != sfdcResponse.signature) {
            return res
                .status(500)
                .end("Signature not correct - Identity cannot be confirmed");
        }
    }

    if (sfdcResponse.id_token) {
        // Decode ID token
        var idToken = sfdcResponse.id_token;

        var tokenSplit = idToken.split(".");
        var header = CryptoJS.enc.Base64.parse(tokenSplit[0]);
        var body = CryptoJS.enc.Base64.parse(tokenSplit[1]);

        console.log("ID Token header: " + header.toString(CryptoJS.enc.Utf8));
        console.log("ID Token body: " + body.toString(CryptoJS.enc.Utf8));
    }

    // In case no error and signature checks out, AND there is an access token present, store refresh token and redirect to query page
    if (sfdcResponse.access_token) {
        console.log("Access Token: " + sfdcResponse.access_token);
        console.log("Refresh Token: " + sfdcResponse.refresh_token);
        refreshToken = sfdcResponse.refresh_token;

        res.writeHead(302, {
            Location: "queryresult",
            "Set-Cookie": [
                "AccToken=" + sfdcResponse.access_token,
                "APIVer=" + apiVersion,
                "InstURL=" + sfdcResponse.instance_url,
                "idURL=" + sfdcResponse.id,
            ],
        });
    } else {
        res.write(
            "Some error occurred. Make sure connected app is approved previously if its JWT flow, Username and Password is correct if its Password flow. "
        );
        res.write(" Salesforce Response : ");
        res.write(remoteBody);
    }
    res.end();
}

/**
 * Create a JWT client assertion
 * @returns JWT client assertion
 */
function createClientAssertion() {
    var assertionData = {
        iss: clientId,
        sub: clientId,
        aud: baseURL + "/services/oauth2/token",
        exp: Math.floor(new Date() / 1000) + 60 * 3,
    };

    return signJWTClaims(assertionData);
}

/**
 * Function that generates a cryptographically random code verifier
 * @returns Cryptographically random code verifier
 */
function generateCodeVerifier() {
    return crypto
        .randomBytes(128)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

/**
 * Function that hashes the code verifier and encodes it into base64URL
 * @param {String} verifier The code verifier string. This string should be long enough to be secure.
 * @returns Code challenge based on provided verifier
 */
function generateCodeChallenge(verifier) {
    return CryptoJS.SHA256(verifier)
        .toString(CryptoJS.enc.Base64)
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

/**
 * Create a JSON Web Token that is signed using the private key stored in 'key.pem'.
 * It first creates the Claims JSON and passes it to the
 * @param {String} sfdcUserName
 */
function getSignedJWT(sfdcUserName) {
    var claims = {
        iss: clientId,
        sub: sfdcUserName,
        aud: jwt_aud,
        exp: Math.floor(Date.now() / 1000) + 60 * 3,
    };

    return signJWTClaims(claims);
}

/**
 * Takes JSON formatted claims, creates a header for them, signs it with the
 * private key stored in 'key.pem' and base64 encodes the concatenation
 * "header.claims.signature".
 * @param {String} claims A JSON representation of the JWT claims containing
 *  issuer (client ID), subject (Salesforce username), audience (login/test)
 *  and expiration.
 */
function signJWTClaims(claims) {
    var absolutePath = path.resolve("key.pem");
    var privateKey = fs.readFileSync(absolutePath);

    var jwt_token = nJwt.create(claims, privateKey, "RS256");
    var jwt_token_b64 = jwt_token.compact();

    console.log("JWT Token: " + jwt_token);

    return jwt_token_b64;
}

app.all("/proxy", function (req, res) {
    var url = req.header("SalesforceProxy-Endpoint");
    request({
        url: url,
        method: req.method,
        json: req.body,
        headers: {
            Authorization: req.header("X-Authorization"),
            "Content-Type": "application/json",
        },
        body: req.body,
    }).pipe(res);
});

/**
 *	 User Agent oAuth Flow
 */
app.get("/uAgent", function (req, res) {
    var isSandbox = req.query.isSandbox;

    if (isSandbox == "true") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/authorize";
    } else {
        endpointUrl = baseURL + "/services/oauth2/authorize";
    }

    request({
        url:
            endpointUrl +
            "?client_id=" +
            process.env.CLIENT_ID +
            "&redirect_uri=" +
            process.env.CALLBACK_URL +
            "&response_type=token",
        method: "GET",
    }).pipe(res);
});

/**
 * Step 1 Web Server Flow - Get Code
 */
app.get("/webServer", function (req, res) {
    // Set parameter values based on environment variables
    var responseType = "code";
    var scope = "full%20refresh_token";
    webserverType = req.query.type;

    if (req.query.isSandbox == "true") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/authorize";
        state = "webServerSandbox";
    } else {
        endpointUrl = baseURL + "/services/oauth2/authorize";
        state = "webServerProd";
    }

    var authorizationUrl =
        endpointUrl +
        "?client_id=" +
        clientId +
        "&redirect_uri=" +
        encodeURI(callbackURL) +
        "&response_type=" +
        responseType +
        "&state=" +
        state +
        "&scope=" +
        scope +
        "&code_challenge=" +
        codeChallenge;

    request({ url: authorizationUrl, method: "GET" }).pipe(res);
});

/**
 * Step 2 Web Server Flow - Get token from Code
 */
app.get("/webServerStep2", function (req, res) {
    var grantType = "authorization_code";
    var code = req.query.code;
    var state = req.query.state;

    if (state == "webServerSandbox") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/token";
    } else {
        endpointUrl = baseURL + "/services/oauth2/token";
    }

    var tokenUrl =
        endpointUrl +
        "?client_id=" +
        clientId +
        "&redirect_uri=" +
        encodeURI(callbackURL) +
        "&grant_type=" +
        grantType +
        "&code=" +
        code +
        "&code_verifier=" +
        codeVerifier;

    if (webserverType == "secret") {
        tokenUrl += "&client_secret=" + clientSecret;
    }

    if (webserverType == "assertion") {
        tokenUrl += "&client_assertion=" + createClientAssertion();
        tokenUrl +=
            "&client_assertion_type=" +
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    }

    request({ url: tokenUrl, method: "POST" }, function (
        err,
        remoteResponse,
        remoteBody
    ) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * JWT Bearer Assertion Flow
 */
app.get("/jwt", function (req, res) {
    var token = getSignedJWT(username);

    if (req.query.isSandbox == "true") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/token";
    } else {
        endpointUrl = baseURL + "/services/oauth2/token";
    }

    var paramBody =
        "grant_type=" +
        base64url.escape("urn:ietf:params:oauth:grant-type:jwt-bearer") +
        "&assertion=" +
        token;
    var req_sfdcOpts = {
        url: endpointUrl,
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: paramBody,
    };

    request(req_sfdcOpts, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 *	 Username Password oAuth Flow
 */
app.post("/uPwd", function (req, res) {
    var instance = req.body.instance;
    var uname = req.body.sfdcUsername;
    var pwd = req.body.sfdcPassword;
    var state = req.query.state;

    if (instance == "sand") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/token";
    } else {
        endpointUrl = baseURL + "/services/oauth2/token";
    }

    var computedURL =
        endpointUrl +
        "?client_id=" +
        clientId +
        "&grant_type=password" +
        "&client_secret=" +
        clientSecret +
        "&username=" +
        uname +
        "&password=" +
        pwd;

    request({ url: computedURL, method: "POST" }, function (
        err,
        remoteResponse,
        remoteBody
    ) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * Device Authentication Flow
 */
app.get("/device", function (req, res) {
    if (req.query.isSandbox == "true") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/token";
    } else {
        endpointUrl = baseURL + "/services/oauth2/token";
    }

    var computedURL =
        endpointUrl + "?client_id=" + clientId + "&response_type=device_code";

    request({ url: computedURL, method: "POST" }, function (
        err,
        remoteResponse,
        remoteBody
    ) {
        if (err) {
            res.write(err);
            res.end();
            //return res.status(500).end('Error');
            return;
        }
        console.log(remoteBody);
        var sfdcResponse = JSON.parse(remoteBody);

        if (sfdcResponse.verification_uri) {
            res.render("deviceOAuth", {
                verification_uri: sfdcResponse.verification_uri,
                user_code: sfdcResponse.user_code,
                device_code: sfdcResponse.device_code,
                isSandbox: req.query.isSandbox,
            });
        }
    });
});

/**
 *  Keep polling till device is verified using code
 */
app.get("/devicePol", function (req, res) {
    var verification_uri = req.query.verification_uri;
    var user_code = req.query.user_code;
    var device_code = req.query.device_code;

    if (req.query.isSandbox == "true") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/token";
    } else {
        endpointUrl = baseURL + "/services/oauth2/token";
    }

    var computedURL =
        endpointUrl +
        "?client_id=" +
        clientId +
        "&grant_type=device" +
        "&code=" +
        device_code;

    request({ url: computedURL, method: "POST" }, function (
        err,
        remoteResponse,
        remoteBody
    ) {
        if (err) {
            return res.status(500).end("Error");
        }
        console.log(remoteBody);
        var sfdcResponse = JSON.parse(remoteBody);

        if (sfdcResponse.access_token) {
            res.writeHead(302, {
                Location: "queryresult",
                "Set-Cookie": [
                    "AccToken=" + sfdcResponse.access_token,
                    "APIVer=" + apiVersion,
                    "InstURL=" + sfdcResponse.instance_url,
                    "idURL=" + sfdcResponse.id,
                ],
            });
            res.end();
        } else {
            res.render("deviceOAuth", {
                verification_uri: verification_uri,
                user_code: user_code,
                device_code: device_code,
                isSandbox: req.query.isSandbox,
            });
        }
    });
});

/**
 * Refresh Token Flow
 */
app.get("/refresh", function (req, res) {
    if (req.query.isSandbox == "true") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/token";
    } else {
        endpointUrl = baseURL + "/services/oauth2/token";
    }

    console.log("Refresh Token: " + refreshToken);

    var paramBody =
        "grant_type=" +
        base64url.escape("refresh_token") +
        "&refresh_token=" +
        refreshToken +
        "&client_id=" +
        clientId;

    var refreshRequest = {
        url: endpointUrl,
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: paramBody,
    };

    request(refreshRequest, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * SAML assertion flow using Axiom SSO
 */
app.get("/samlAssert", function (req, res) {
    // Set parameters for the SAML request body
    const assertionType = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser";
    var assertion = "";
    var assertionXml =
        '<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" Destination="https://nicolasvandenbossche-dev-ed.my.salesforce.com" ID="_382b9d22-2713309a" IssueInstant="2020-07-30T10:57:51.867Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://axiomsso.herokuapp.com</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/><ds:Reference URI="#_382b9d22-2713309a"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>iVmDp4oaHSZM6WBeAu7xynoERC4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>WKNHlmuwo88/hphmtfqUL8E6ANg4NbJ4V21l2BjO9/BMkhCQNbLiVw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID0zCCA5GgAwIBAgIEF/uFITALBgcqhkjOOAQDBQAwgboxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzESMBAGA1UEChMJQXhpb20gU1NPMVEwTwYDVQQLE0hGT1IgREVNT05TVFJBVElPTiBQVVJQT1NFUyBPTkxZLiBETyBOT1QgVVNFIEZPUiBQUk9EVUNUSU9OIEVOVklST05NRU5UUy4xHzAdBgNVBAMTFkF4aW9tIERlbW8gQ2VydGlmaWNhdGUwHhcNMTQwNjIwMDQzMDI3WhcNNDExMTA1MDQzMDI3WjCBujELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRIwEAYDVQQKEwlBeGlvbSBTU08xUTBPBgNVBAsTSEZPUiBERU1PTlNUUkFUSU9OIFBVUlBPU0VTIE9OTFkuIERPIE5PVCBVU0UgRk9SIFBST0RVQ1RJT04gRU5WSVJPTk1FTlRTLjEfMB0GA1UEAxMWQXhpb20gRGVtbyBDZXJ0aWZpY2F0ZTCCAbgwggEsBgcqhkjOOAQBMIIBHwKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCjrh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQBTDv+z0kqA4GFAAKBgQCXr1mp4UvByY6dGbDOyq3wMs6O7MCxmEkU2x32AkEp6s7Xfiy3MYwKwZQ4sL4BmQYzZ7QOXPP8dKgrKDQKLk9tXWOgvIoOCiNAdQDYlRm2sYgrI2SUcyM1bKDqLwDD8Z5OoLeuQAtgMfAq/f1C6nREWrQudPxOwaoNdHkYcR+066MhMB8wHQYDVR0OBBYEFE2JAc97wfHK5b42nKbANn4SMcqcMAsGByqGSM44BAMFAAMvADAsAhR+Cjvp8UwNgKHfx2PWJoRi0/1q8AIUNhTXWlGzJ3SdBlgRsdFgKyFtcxE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_24dff26f-d7fc976" IssueInstant="2020-07-30T10:57:51.867Z" Version="2.0"><saml2:Issuer>https://axiomsso.herokuapp.com</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">13371337</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData NotOnOrAfter="2020-07-30T10:58:51.867Z" Recipient="https://nicolasvandenbossche-dev-ed.my.salesforce.com"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2020-07-30T10:57:51.867Z" NotOnOrAfter="2020-07-30T10:58:51.867Z"><saml2:AudienceRestriction><saml2:Audience>https://saml.salesforce.com</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2020-07-30T10:57:51.867Z"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement><saml2:AttributeStatement><saml2:Attribute Name="ssoStartPage" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">http://axiomsso.herokuapp.com/RequestSamlResponse.action</saml2:AttributeValue></saml2:Attribute><saml2:Attribute Name="logoutURL" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>';

    // Determine the endpoint URL depending on whether this needs to be executed on sandbox or production
    if (req.query.isSandbox == "true") {
        endpointUrl = "https://test.salesforce.com/services/oauth2/token";
    } else {
        endpointUrl = baseURL + "/services/oauth2/token";
    }

    // Construct the request body containing grant type, assertion type and assertion. All should be URL encoded.
    var samlParamBody =
        "grant_type=" +
        encodeURIComponent("assertion") +
        "&assertion_type=" +
        encodeURIComponent(assertionType) +
        "&assertion=" +
        encodeURIComponent(Buffer.from(assertionXml).toString("base64"));

    // Launch the POST request with the constructured body to the defined endpoint.
    request(
        {
            url: endpointUrl,
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: samlParamBody,
        },
        function (err, remoteResponse, remoteBody) {
            // Process error
            if (err) {
                return res.status(500).end("Error: " + err);
            }

            // Process success by storing the access token in the browser's cookies.
            var sfdcResponse = JSON.parse(remoteBody);

            if (sfdcResponse.access_token) {
                res.writeHead(302, {
                    Location: "queryresult",
                    "Set-Cookie": [
                        "AccToken=" + sfdcResponse.access_token,
                        "APIVer=" + apiVersion,
                        "InstURL=" + sfdcResponse.instance_url,
                        "idURL=" + sfdcResponse.id,
                    ],
                });
                res.end();
            } else {
                return res.status(401).end("Error: " + JSON.stringify(sfdcResponse));
            }
        }
    );
});

app.route(/^\/(index.*)?$/).get(function (req, res) {
    res.render("index", {
        callbackURL: callbackURL,
        baseURL: baseURL,
        username: username,
        clientId: clientId,
        clientSecret: clientSecret,
        codeVerifier: codeVerifier,
        codeChallenge: codeChallenge,
    });
});

/**
 * Handle OAuth callback from Salesforce and parse the result.
 * Result is parsed in oauthcallback.ejs.
 */
app.get("/oauthcallback", function (req, res) {
    var code = req.query.code;
    var returnedState = req.query.state;

    res.render("oauthcallback", {
        code: code,
        returnedState: returnedState,
        originalState: state,
    });
});

/**
 * Use the access token to execute a query using Salesforce REST API.
 */
app.get("/queryresult", function (req, res) {
    res.render("queryresult");
});

app.listen(app.get("port"), function () {
    console.log("Express server listening on port " + app.get("port"));
});

// Load files with keys and options
var options = {
    key: fs.readFileSync("./key.pem", "utf8"),
    cert: fs.readFileSync("./server.crt", "utf8"),
};

// Define code verifier and code challenge
var codeVerifier = generateCodeVerifier();
var codeChallenge = generateCodeChallenge(codeVerifier);

// Create the server and log that it's up and running
https.createServer(options, app).listen(8081);
console.log("Server listening for HTTPS connections on port ", 8081);
