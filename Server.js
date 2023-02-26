const { UserAgentService } = require('./services/useragent');
const { WebServerService } = require('./services/webserver');
const { JwtService } = require('./services/jwt');
const { SamlBearerService } = require('./services/samlbearer');
const { UsernamePasswordService } = require('./services/usernamepassword');
const { DeviceService } = require('./services/device');
const { RefreshService } = require('./services/refresh');
const { SamlAssertService } = require('./services/samlassert');

// Load dependencies
const express = require('express'),
    request = require('request'),
    bodyParser = require('body-parser'),
    morgan = require('morgan'),
    app = express(),
    https = require('https'),
    fs = require('fs'),
    rateLimit = require('express-rate-limit'),
    data = require('./data/authFlows.json'),
    escape = require('escape-html');

// Set global variables, some loaded from environment variables (.env file)
const clientId = process.env.CLIENT_ID,
    clientSecret = process.env.CLIENT_SECRET,
    callbackURL = process.env.CALLBACK_URL,
    baseURL = process.env.BASE_URL,
    username = process.env.USERNAME,
    limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
        standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
        legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    });

var authInstance;

// Set default view engine to ejs. This will be used when calling res.render().
app.set('view engine', 'ejs');

// Apply the rate limiting middleware to all requests
app.use(limiter);

// Let Express know where the client files are located
app.use(express.static(__dirname + '/client'));

// Setting up of app
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Set the port to use based on the environment variables
app.set('port', process.env.PORT);

/**
 * Send the GET request and process the response.
 *
 * @param {JSON Object} getRequest The JSON object containing details on the GET request.
 * @param {*} res The response object from Node.js.
 */
function handleGetRequest(getRequest, res) {
    request({ method: 'GET', url: getRequest }).pipe(res);
}

/**
 * Send the POST request and process the response. Show an error if anything goes wrong.
 *
 * @param {JSON Object} postRequest The JSON object containing details on the POST request.
 * @param {*} res The response object from Node.js.
 */
function handlePostRequest(postRequest, res) {
    request(postRequest, function (error, remoteResponse, remoteBody) {
        // Handle error or process response
        if (error) {
            res.status(500).end('Error occurred: ' + JSON.stringify(error));
        } else {
            let { error, accessTokenHeader, refreshToken, redirect } = authInstance.processCallback(remoteBody);
            processResponse(error, accessTokenHeader, refreshToken, redirect, res);
        }
    });
}

/**
 * Process the response from the GET / POST request. There are 3 possible input combinations.
 * 1. The page needs to be redirected.
 * 2. There was an error returned that needs to be displayed to the page.
 * 3. An access token was returned and we can query the resource server.
 *
 * @param {String} error The error that's returned from the GET or POST request.
 * @param {JSON Object} accessTokenHeader The header variables containing the cookies that will set the access token.
 * @param {String} refreshToken The refresh token (if any).
 * @param {JSON Object} redirect Contains information about redirect (location and payload).
 * @param {} res The response object from Node.js.
 */
function processResponse(error, accessTokenHeader, refreshToken, redirect, res) {
    if (redirect) {
        // Page needs to be rerendered to retry retrieving access token (device flow)
        console.log(
            'Rendering the following page: ' + redirect.location + '.\nPayload: ' + JSON.stringify(redirect.payload)
        );
        redirect.payload.data = data;
        res.render(redirect.location, redirect.payload);
    } else if (error) {
        // If response doesn't return a successful response, show the error page.
        console.log('No successful response from request. Showing error page with error: ' + error);
        res.status(500).end(error);
    } else {
        // If response returns successful response, we set the access token in the cookies and store the refresh token
        console.log('Setting access token in cookies to use it in client-side JavaScript...');
        this.refreshToken = refreshToken;
        res.writeHead(302, accessTokenHeader);
        res.end();
    }
}

/**
 *	User Agent oAuth Flow. Gets launched when navigating to '/user-agent'.

 */
app.get('/user-agent', function (req, res) {
    console.log('Starting User Agent flow...');

    // Instantiate the service to create the URL to call
    authInstance = new UserAgentService();
    const userAgentUrlWithParameters = authInstance.generateUserAgentRequest();

    // Launch the HTTP GET request based on the constructed URL with parameters
    console.log('Sending GET request: ' + userAgentUrlWithParameters);
    handleGetRequest(userAgentUrlWithParameters, res);
    console.log('Once user authorizes the app, a redirect will be performed to the oauthcallback page');
});

/**
 *  Step 1 Web Server Flow - Get Code. Gets launched when navigating to the endpoint for a particular Web Server flow.
 *  This is the first step in the flow, where the authorization code is retrieved from the authorization endpoint.
 */

app.get('/web-server-pkce-only', function (req, res) {
    console.debug('Starting Web Server flow...');

    // Instantiate the service to create the URL to call
    // TODO: Replace type with interfaces
    authInstance = new WebServerService('none');
    const authorizationUrl = authInstance.generateAuthorizationRequest();

    // Launch the request to get the authorization code
    console.log('Launching authorization code request with URL:\n%s', authorizationUrl);
    handleGetRequest(authorizationUrl, res);
});

app.get('/web-server-client-assertion', function (req, res) {
    console.debug('Starting Web Server flow...');

    // Instantiate the service to create the URL to call
    // TODO: Replace type with interfaces
    authInstance = new WebServerService('assertion');
    const authorizationUrl = authInstance.generateAuthorizationRequest();

    // Launch the request to get the authorization code
    console.log('Launching authorization code request with URL:\n%s', authorizationUrl);
    handleGetRequest(authorizationUrl, res);
});

app.get('/web-server-client-secret', function (req, res) {
    console.debug('Starting Web Server flow...');

    // Instantiate the service to create the URL to call
    // TODO: Replace type with interfaces
    authInstance = new WebServerService('secret');
    const authorizationUrl = authInstance.generateAuthorizationRequest();

    // Launch the request to get the authorization code
    console.log('Launching authorization code request with URL:\n%s', authorizationUrl);
    handleGetRequest(authorizationUrl, res);
});

/**
 * JWT Bearer Assertion Flow. Gets launched when navigating to '/jwt-bearer'.
 * Creates a JWT token for the username defined in the environment variables, then posts it to the token endpoint.
 */
app.get('/jwt-bearer', function (req, res) {
    // Instantiate JWT service and generate post request
    authInstance = new JwtService();
    let postRequest = authInstance.generateJwtRequest();

    // Handle the response of the post request
    handlePostRequest(postRequest, res);
});

/**
 * SAML Bearer Assertion Flow. Gets launched when navigating to '/saml-bearer'.
 * Creates a SAML bearer token for the username defined in the environment variables, then posts it to the token endpoint.
 */
app.get('/saml-bearer', function (req, res) {
    // Instantiate SAML Bearer service and generate post request
    authInstance = new SamlBearerService();
    let postRequest = authInstance.generateSamlBearerRequest();

    // Handle the response of the post request
    handlePostRequest(postRequest, res);
});

/**
 * Username Password oAuth Flow. Gets launched when navigating to '/username-password'.
 * Sends username and password in the URL as free text to the token endpoint.
 */
app.post('/username-password', function (req, res) {
    // Instantiate Username-Password service and generate post request
    authInstance = new UsernamePasswordService();
    let postRequest = authInstance.generateUsernamePasswordRequest(req.body.sfdcUsername, req.body.sfdcPassword);

    // Handle the response of the post request
    handlePostRequest(postRequest, res);
});

/**
 * Device Authentication Flow. Gets launched when navigating to '/device'.
 * Retrieves a device code, user code and verification URI and displays it to the user.
 */
app.get('/device', function (req, res) {
    // Instantiate Device service and generate post request
    authInstance = new DeviceService();
    let postRequest = authInstance.generateDeviceRequest();

    // Handle the response of the post request
    console.log('Sending request to get device code...');
    handlePostRequest(postRequest, res);
});

/**
 * This method is called every time we poll the token endpoint to see if the device
 * was authorized. It only loads the page in case a response was received
 */
app.get('/devicePol', function (req, res) {
    console.log('Starting polling for authorization...');
    // Asynchrous polling of the endpoint using a promise. Set device response on success.
    authInstance.pollContinually().then((response) => {
        console.log('Authorization granted by user.');
        processResponse(response.error, response.accessTokenHeader, response.refreshToken, response.redirect, res);
    });
});

/**
 * Refresh Token Flow. Gets launched when navigating to '/refresh-token'.
 * Requires another flow to be run that provided a refresh token, previous to launching this flow.
 * Sends the refresh token to the token endpoint.
 */
app.get('/refresh-token', function (req, res) {
    // Instantiate Username-Password service and generate post request
    authInstance = new RefreshService();
    let postRequest = authInstance.generateRefreshRequest(this.refreshToken);

    // Handle the response of the post request
    handlePostRequest(postRequest, res);
});

/**
 * SAML assertion flow using Axiom SSO. Gets launched when navigating to '/saml-assertion'.
 * Requires a SAML assertion that is stored on the server's file system ('data/axiomSamlAssertino.xml').
 */
app.get('/saml-assertion', function (req, res) {
    // Instantiate Saml Assert service and generate post request
    authInstance = new SamlAssertService();

    let postRequest;
    try {
        postRequest = authInstance.generateSamlAssertRequest();
    } catch (error) {
        console.log('Error from generateSamlAssertRequest(): ' + error);
        res.status(500).end('Error occurred: ' + error.message);
    }

    if (postRequest) {
        // Handle the response of the post request
        handlePostRequest(postRequest, res);
    }
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
        data: data,
    });
});

/**
 * Handle OAuth callback from Salesforce and parse the result.
 * Result is parsed in oauthcallback.ejs.
 */
app.get('/oauthcallback', function (req, res) {
    let code = req.query.code;
    let returnedState = escape(req.query.state);
    let originalState = authInstance ? authInstance.state : undefined;

    console.debug('Callback received with code %s and state %s', code, returnedState);

    if (code) {
        // If an authorization code is returned, check the state and continue web-server flow.
        if (returnedState === originalState) {
            // Web Server instance was already created during first step of the flow, just send the request
            let postRequest = authInstance.generateTokenRequest(code);

            // Send the request to the endpoint and specify callback function
            console.debug(
                'Launching access token request with URL:\n%s\n...and body:\n%s',
                postRequest.url,
                postRequest.body
            );
            handlePostRequest(postRequest, res);
        } else {
            res.status(500).end(
                'Error occurred: ' +
                    '\nCross App / Site Request Forgery detected!' +
                    '\nReturned state: ' +
                    returnedState +
                    '\nOriginal state: ' +
                    originalState
            );
        }
    } else {
        // If no authorization code is returned, render oauthcallback.
        // We need client-side Javascript to get to the fragment (after #) of the URL.
        res.render('oauthcallback');
    }
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

// Create the server and log that it's up and running
https.createServer(options, app).listen(8081);
console.log('Server listening for HTTPS connections on port ', 8081);
