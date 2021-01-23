// Load dependencies
var express = require('express'),
    http = require('http'),
    request = require('request'),
    bodyParser = require('body-parser'),
    morgan = require('morgan'),
    app = express(),
    path = require('path'),
    https = require('https'),
    fs = require('fs'),
    base64url = require('base64-url'),
    nJwt = require('njwt'),
    saml = require('saml').Saml20,
    CryptoJS = require('crypto-js'),
    crypto = require('crypto');

// Set global variables, some loaded from environment variables (.env file)
var apiVersion = 'v45.0',
    clientId = process.env.CLIENT_ID,
    clientSecret = process.env.CLIENT_SECRET,
    callbackURL = process.env.CALLBACK_URL,
    baseURL = process.env.BASE_URL,
    username = process.env.USERNAME,
    persistTokensToFile = process.env.PERSIST,
    jwt_aud = baseURL, //'https://login.salesforce.com',
    saml_aud = baseURL, //'https://login.salesforce.com',
    isSandbox = false,
    state = '',
    refreshToken = '',
    webserverType = '';

// Set default view engine to ejs. This will be used when calling res.render().
app.set('view engine', 'ejs');

// Let Express know where the client files are located
app.use(express.static(__dirname + '/client'));

// Setting up of app
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Set the port to use based on the environment variables
app.set('port', process.env.PORT);

/**
 * Extract Access token from POST response and redirect to page queryresult.
 * @param {*} err Error object returned to the callback function in case anything went wrong.
 * @param {*} remoteResponse The response code from the remote call.
 * @param {String} remoteBody The (JSON) body response from the remote call.
 * @param {*} res The resource from Express, modify to display a result.
 */
function accessTokenCallback(err, remoteResponse, remoteBody, res) {
    // Display error if error is returned to callback function
    if (err) {
        return res.status(500).end('Error');
    }

    // Retrieve the response and store in JSON object
    let sfdcResponse = JSON.parse(remoteBody);

    let identityUrl = sfdcResponse.id;
    let issuedAt = sfdcResponse.issued_at;
    let idToken = sfdcResponse.id_token;
    let accessToken = sfdcResponse.access_token;

    // If identity URL is specified, check its signature based on identity URL and 'issued at'
    if (identityUrl && issuedAt) {
        // Create SHA-256 hash of identity URL and 'issued at' based on client secret
        let hash = CryptoJS.HmacSHA256(identityUrl + issuedAt, clientSecret);
        let hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

        // Show error if base64 encoded hash doesn't match with the signature in the response
        if (hashInBase64 != sfdcResponse.signature) {
            return res.status(500).end('Signature not correct - Identity cannot be confirmed');
        }
    }

    // If ID Token is specified, parse it and print it in the console
    if (idToken) {
        // Decode ID token
        let tokenSplit = idToken.split('.');
        let header = CryptoJS.enc.Base64.parse(tokenSplit[0]);
        let body = CryptoJS.enc.Base64.parse(tokenSplit[1]);

        console.log('ID Token header: ' + header.toString(CryptoJS.enc.Utf8));
        console.log('ID Token body: ' + body.toString(CryptoJS.enc.Utf8));
    }

    // In case no error and signature checks out, AND there is an access token present, store refresh token in global state and redirect to query page
    if (accessToken) {
        if (sfdcResponse.refresh_token) {
            refreshToken = sfdcResponse.refresh_token;
        }

        res.writeHead(302, {
            Location: 'queryresult',
            'Set-Cookie': [
                'AccToken=' + accessToken,
                'APIVer=' + apiVersion,
                'InstURL=' + sfdcResponse.instance_url,
                'idURL=' + sfdcResponse.id,
            ],
        });
    } else {
        res.write(
            'Some error occurred. Make sure connected app is approved previously if its JWT flow, Username and Password is correct if its Password flow. '
        );
        res.write(' Salesforce Response : ');
        res.write(remoteBody);
    }
    res.end();
}

/**
 * Extract Access token from POST response and redirect to page queryresult.
 * @param {*} err Error object returned to the callback function in case anything went wrong.
 * @param {*} remoteResponse The response code from the remote call.
 * @param {String} remoteBody The (JSON) body response from the remote call.
 * @param {*} res The resource from Express, modify to display a result.
 */
function deviceFlowCallback(err, remoteResponse, remoteBody, res) {
    // If an error is received, show it
    if (err) {
        return res.status(500).end('Error:' + err);
    }

    // Parse the response for the device flow, either a user code to be displayed or the access token
    let sfdcResponse = JSON.parse(remoteBody);
    let verificationUri = sfdcResponse.verification_uri;
    let userCode = sfdcResponse.user_code;
    let deviceCode = sfdcResponse.device_code;
    let interval = sfdcResponse.interval;
    let accessToken = sfdcResponse.access_token;

    // Render query result if access token is present, or show user code page if not
    if (accessToken) {
        res.writeHead(302, {
            Location: 'queryresult',
            'Set-Cookie': [
                'AccToken=' + sfdcResponse.access_token,
                'APIVer=' + apiVersion,
                'InstURL=' + sfdcResponse.instance_url,
                'idURL=' + sfdcResponse.id,
            ],
        });
        res.end();
    } else if (verificationUri) {
        res.render('deviceOAuth', {
            verification_uri: verificationUri,
            user_code: userCode,
            device_code: deviceCode,
            isSandbox: isSandbox,
            interval: interval,
        });
    }
}

/**
 * Create a JWT client assertion
 * @returns JWT client assertion
 */
function createClientAssertion() {
    var assertionData = {
        iss: clientId,
        sub: clientId,
        aud: baseURL + '/services/oauth2/token',
        exp: Math.floor(new Date() / 1000) + 60 * 3,
    };

    return signJwtClaims(assertionData);
}

/**
 * Function that generates a cryptographically random code verifier
 * @returns Cryptographically random code verifier
 */
function generateCodeVerifier() {
    return crypto.randomBytes(128).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Function that hashes the code verifier and encodes it into base64URL
 * @param {String} verifier The code verifier string. This string should be long enough to be secure.
 * @returns Code challenge based on provided verifier
 */
function generateCodeChallenge(verifier) {
    return CryptoJS.SHA256(verifier)
        .toString(CryptoJS.enc.Base64)
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

/**
 * Create a JSON Web Token that is signed using the private key stored in 'key.pem'.
 * It first creates the Claims JSON and passes it to the signJwtClaims method.
 * @param {String} sfdcUserName
 */
function getSignedJWT(sfdcUserName) {
    var claims = {
        iss: clientId,
        sub: sfdcUserName,
        aud: jwt_aud,
        exp: Math.floor(Date.now() / 1000) + 60 * 3, // valid for 3 minutes
    };

    console.log('Claims: ' + claims);

    return signJwtClaims(claims);
}

/**
 * Takes JSON formatted claims, creates a header for them, signs it with the
 * private key stored in 'key.pem' and base64 encodes the concatenation
 * "header.claims.signature".
 * @param {String} claims A JSON representation of the JWT claims containing
 *  issuer (client ID), subject (Salesforce username), audience (login/test)
 *  and expiration.
 */
function signJwtClaims(claims) {
    // Read private key into memory
    let privateKey = fs.readFileSync(path.resolve('key.pem'));

    // Leverage njwt library to create JWT token based on claims and private key
    let jwtToken = nJwt.create(claims, privateKey, 'RS256');

    // Return base64 version of the JWT token
    return jwtToken.compact();
}

/**
 * Create a SAML Bearer Token that is signed using the private key stored in 'key.pem'.
 * It first creates the list of SAML claims and passes it to the create method of the saml library.
 * @returns {String} The signed SAML Bearer token in utf-8 encoding.
 */
function getSignedSamlToken() {
    let signedSamlToken;

    // Retrieve private key and server certificate
    let privateKey = fs.readFileSync(__dirname + '/key.pem');
    let publicCert = fs.readFileSync(__dirname + '/server.crt');

    // Set claims / options for SAML Bearer token. All of these are required for Salesforce.
    let samlClaims = {
        cert: publicCert,
        key: privateKey,
        issuer: clientId,
        lifetimeInSeconds: 600,
        audiences: saml_aud,
        nameIdentifier: username,
    };

    // Create the SAML token which is signed with the private key (not encrypted)
    signedSamlToken = saml.create(samlClaims);

    return signedSamlToken;
}

/**
 * Set whether this flow is being executed for a sandbox or not.
 * @param {String} sandboxString The string containing 'true' or 'false' on whether or not
 * we're in the sandbox flow.
 */
function setSandbox(sandboxString) {
    isSandbox = sandboxString === 'true';
}

/**
 * Return the base URL for sending any HTTP requests to
 */
function getBaseUrl() {
    return isSandbox ? 'https://test.salesforce.com/' : baseURL;
}

/**
 * Return the Authorization Endpoint for the set base URL
 */
function getAuthorizeEndpoint() {
    return getBaseUrl() + '/services/oauth2/authorize';
}

/**
 * Return the Token Endpoint for the set base URL
 * @returns The token endpoint URL
 */
function getTokenEndpoint() {
    return getBaseUrl() + '/services/oauth2/token';
}

/**
 * Creates a HTTP POST request JSON object that can be passed along to the Express "request".
 * @param {String} endpointUrl The url of the endpoint (authorization or token).
 * @param {String} body The parameters to be passed to the endpoint as URL parameters (key1=value1&key2=value2&...).
 * @returns JSON object containing information needed for sending the POST request.
 */
function createPostRequest(endpointUrl, body) {
    return {
        method: 'POST',
        url: endpointUrl,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body,
    };
}

app.all('/proxy', function (req, res) {
    var url = req.header('SalesforceProxy-Endpoint');
    request({
        url: url,
        method: req.method,
        json: req.body,
        headers: {
            Authorization: req.header('X-Authorization'),
            'Content-Type': 'application/json',
        },
        body: req.body,
    }).pipe(res);
});

/**
 *	User Agent oAuth Flow. Gets launched when navigating to '/uAgent'.
 *  Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 */
app.get('/uAgent', function (req, res) {
    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // Set response type and get url of authorization endpoint
    let responseType = 'token';
    let endpointUrl = getAuthorizeEndpoint();

    // Construct the url for the user agent flow, including parameters in url
    let userAgentUrlWithParameters =
        endpointUrl + '?client_id=' + clientId + '&redirect_uri=' + callbackURL + '&response_type=' + responseType;

    // Launch the HTTP GET request based on the constructed URL with parameters
    request({
        method: 'GET',
        url: userAgentUrlWithParameters,
    }).pipe(res);
});

/**
 *  Step 1 Web Server Flow - Get Code. Gets launched when navigating to '/webServer'.
 *  Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 *  This is the first step in the flow, where the authorization code is retrieved from the authorization endpoint.
 */
app.get('/webServer', function (req, res) {
    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // Store the web server flow type in a global variable to be retrieved in the second step of the flow
    webserverType = req.query.type;

    // Set parameter values for retrieving authorization code
    let responseType = 'code';
    let scope = 'full%20refresh_token';
    let endpointUrl = getAuthorizeEndpoint();

    // Create a state to prevent CSRF
    state = base64url.escape(crypto.randomBytes(32).toString('base64'));

    // Generate the url to request the authorization code, including parameters
    let authorizationUrl =
        endpointUrl +
        '?client_id=' +
        clientId +
        '&redirect_uri=' +
        encodeURI(callbackURL) +
        '&response_type=' +
        responseType +
        '&state=' +
        state +
        '&scope=' +
        scope +
        '&code_challenge=' +
        codeChallenge;

    // Launch the request to get the authorization code
    request({ method: 'GET', url: authorizationUrl }).pipe(res);
});

/**
 * Step 2 Web Server Flow - Get access token using authorization code.
 * Gets launched as part of the callback actions from the first step of the web server flow.
 * This is the second step in the flow where the access token is retrieved by passing the previously
 * obtained authorization code to the token endpoint.
 */
app.get('/webServerStep2', function (req, res) {
    // Set parameter values for retrieving access token
    let grantType = 'authorization_code';
    let code = req.query.code;
    let endpointUrl = getTokenEndpoint();

    // Set the different parameters in the body of the post request
    let paramBody =
        'client_id=' +
        clientId +
        '&redirect_uri=' +
        encodeURI(callbackURL) +
        '&grant_type=' +
        grantType +
        '&code=' +
        code +
        '&code_verifier=' +
        codeVerifier;

    // Add additional parameters in case of 'Client secret' or 'Client assertion' flow
    if (webserverType == 'secret') {
        paramBody += '&client_secret=' + clientSecret;
    } else if (webserverType == 'assertion') {
        paramBody += '&client_assertion=' + createClientAssertion();
        paramBody += '&client_assertion_type=' + 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    }

    // Create the full POST request with all required parameters
    let postRequest = createPostRequest(endpointUrl, paramBody);

    // Send the request to the endpoint and specify callback function
    request(postRequest, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * JWT Bearer Assertion Flow. Gets launched when navigating to '/jwt'.
 * Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 * Creates a JWT token for the username defined in the environment variables, then posts it to the token endpoint.
 */
app.get('/jwt', function (req, res) {
    const grantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // Define POST request parameters
    let endpointUrl = getTokenEndpoint();

    let token = getSignedJWT(username);
    let paramBody = 'grant_type=' + base64url.escape(grantType) + '&assertion=' + token;

    let postRequest = createPostRequest(endpointUrl, paramBody);

    request(postRequest, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * SAML Bearer Assertion Flow. Gets launched when navigating to '/samlBearer'.
 * Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 * Creates a SAML bearer token for the username defined in the environment variables, then posts it to the token endpoint.
 */
app.get('/samlBearer', function (req, res) {
    // Set parameters for the SAML request body
    const assertionType = 'urn:ietf:params:oauth:grant-type:saml2-bearer';
    let token = getSignedSamlToken();
    let base64SignedSamlToken = base64url.encode(token);

    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // If persist option is set to true, persist the SAML bearer token and its base64 encoding to file
    if (persistTokensToFile) {
        fs.writeFile(__dirname + '/data/samlBearer.xml', token);
        fs.writeFile(__dirname + '/data/samlBase64.txt', base64SignedSamlToken);
    }

    // Determine the endpoint URL depending on whether this needs to be executed on sandbox or production
    let endpointUrl = getTokenEndpoint();

    // Set the body of the POST request by defining the grant_type and assertion parameters
    let paramBody = 'grant_type=' + assertionType + '&assertion=' + base64SignedSamlToken;

    // Set the request parameters for the token endpoint
    let postRequest = createPostRequest(endpointUrl, paramBody);

    // Launch the request and handle the response using accessTokenCallback
    request(postRequest, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * Username Password oAuth Flow. Gets launched when navigating to '/uPwd'.
 * Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 * Sends username and password in the URL as free text to the token endpoint.
 */
app.post('/uPwd', function (req, res) {
    // Set sandbox context
    setSandbox(req.body.isSandbox);

    // Construct parameters for POST request
    const grantType = 'password';
    let username = req.body.sfdcUsername;
    let password = req.body.sfdcPassword;
    let endpointUrl = getTokenEndpoint();

    // Create body for POST request
    let paramBody =
        'client_id=' +
        clientId +
        '&grant_type=' +
        grantType +
        '&client_secret=' +
        clientSecret +
        '&username=' +
        username +
        '&password=' +
        encodeURIComponent(password);

    // Set the request parameters for the token endpoint
    let postRequest = createPostRequest(endpointUrl, paramBody);

    // Launch the request to the token endpoint and process in the callback function
    request(postRequest, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * Device Authentication Flow. Gets launched when navigating to '/device'.
 * Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 * Retrieves a device code, user code and verification URI and displays it to the user.
 */
app.get('/device', function (req, res) {
    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // Define parameters
    const responseType = 'device_code';
    let endpointUrl = getTokenEndpoint();
    let paramBody = 'client_id=' + clientId + '&response_type=' + responseType;

    // Create post request to be sent to the token endpoint
    let postRequest = createPostRequest(endpointUrl, paramBody);

    // Launch request and set callback method
    request(postRequest, function (err, remoteResponse, remoteBody) {
        deviceFlowCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * This method is called every time we poll the token endpoint to see if the device
 * was authorized. Keep polling until the device is verified.
 */
app.get('/devicePol', function (req, res) {
    // Retrieve query parameters for further processing
    const grantType = 'device';
    let deviceCode = req.query.device_code;

    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // Set parameters for POST request
    let endpointUrl = getTokenEndpoint();
    let paramBody = 'client_id=' + clientId + '&grant_type=' + grantType + '&code=' + deviceCode;

    let postRequest = createPostRequest(endpointUrl, paramBody);

    // Launch request towards token endpoint
    request(postRequest, function (err, remoteResponse, remoteBody) {
        deviceFlowCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * Refresh Token Flow. Gets launched when navigating to '/refresh'.
 * Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 * Requires another flow to be run that provided a refresh token, previous to launching this flow.
 * Sends the refresh token to the token endpoint.
 */
app.get('/refresh', function (req, res) {
    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // Set parameters for POST request
    const grantType = 'refresh_token';
    let endpointUrl = getTokenEndpoint();
    let paramBody =
        'grant_type=' + base64url.escape(grantType) + '&refresh_token=' + refreshToken + '&client_id=' + clientId;

    // Create the POST request
    let postRequest = createPostRequest(endpointUrl, paramBody);

    // Launch POST request towards token endpoint
    request(postRequest, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * SAML assertion flow using Axiom SSO. Gets launched when navigating to '/samlAssert'.
 * Depending on the 'isSandbox' parameter in the URL, the production or sandbox flow is triggered.
 * Requires a SAML assertion that is stored on the server's file system ('data/axiomSamlAssertino.xml').
 */
app.get('/samlAssert', function (req, res) {
    // Set sandbox context
    setSandbox(req.query.isSandbox);

    // Set parameters for the SAML request body
    const assertionType = 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser';
    let endpointUrl = getTokenEndpoint();

    // Read assertion XML from file located at 'data/axiomSamlAssertion.xml'. Alternatively, copy-paste XML string below and assign to variable.
    let assertionXml = fs.readFileSync('data/axiomSamlAssertion.xml', 'utf8');
    let base64AssertionXml = Buffer.from(assertionXml).toString('base64');

    // Construct the request body containing grant type, assertion type and assertion. All should be URL encoded.
    let samlParamBody =
        'grant_type=' +
        encodeURIComponent('assertion') +
        '&assertion_type=' +
        encodeURIComponent(assertionType) +
        '&assertion=' +
        encodeURIComponent(base64AssertionXml);

    let postRequest = createPostRequest(endpointUrl, samlParamBody);

    // Launch the POST request with the constructured body to the defined endpoint.
    request(postRequest, function (err, remoteResponse, remoteBody) {
        accessTokenCallback(err, remoteResponse, remoteBody, res);
    });
});

/**
 * Display the home page.
 */
app.route(/^\/(index.*)?$/).get(function (req, res) {
    res.render('index', {
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
app.get('/oauthcallback', function (req, res) {
    let code = req.query.code;
    let returnedState = req.query.state;

    res.render('oauthcallback', {
        code: code,
        returnedState: returnedState,
        originalState: state,
    });
});

/**
 * Use the access token to execute a query using Salesforce REST API.
 * Access token is stored in session cookies, so no need to pass it on.
 */
app.get('/queryresult', function (req, res) {
    res.render('queryresult');
});

/**
 * Log message to indicate on which port the application is running.
 */
app.listen(app.get('port'), function () {
    console.log('Express server listening on port ' + app.get('port'));
});

// Load files with private key and corresponding public certificate
var options = {
    key: fs.readFileSync('./key.pem', 'utf8'),
    cert: fs.readFileSync('./server.crt', 'utf8'),
};

// Define code verifier and code challenge
var codeVerifier = generateCodeVerifier();
var codeChallenge = generateCodeChallenge(codeVerifier);

// Create the server and log that it's up and running
https.createServer(options, app).listen(8081);
console.log('Server listening for HTTPS connections on port ', 8081);
