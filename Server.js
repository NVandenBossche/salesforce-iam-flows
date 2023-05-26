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
    bodyParser = require('body-parser'),
    morgan = require('morgan'),
    app = express(),
    https = require('https'),
    fs = require('fs'),
    rateLimit = require('express-rate-limit'),
    data = require('./data/authFlows.json'),
    flowsList = Object.values(data),
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
    }),
    flowClasses = {
        'user-agent': UserAgentService,
        'web-server': WebServerService,
        'refresh-token': RefreshService,
        'jwt-bearer': JwtService,
        'saml-bearer': SamlBearerService,
        'saml-assertion': SamlAssertService,
        'username-password': UsernamePasswordService,
        device: DeviceService,
    };

// Global variable containing the instance
let authInstance, inputUsername, inputPassword;

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
 * Display the home page.
 */
app.route(/^\/(index.*)?$/).get(function (req, res) {
    res.render('index', {
        callbackURL: callbackURL,
        baseURL: baseURL,
        username: username,
        clientId: clientId,
        clientSecret: clientSecret,
        data: flowsList,
    });
});

app.get('/launch/:id', (req, res) => {
    // Retrieve the data for the flow based on the id in the query parameters
    const flowData = data[req.params.id];

    // Launch specified flow with specified variant
    let flowName = flowData.flow;
    let variant = flowData.variant;

    // If the authInstance variable is already set, retrieve the refreshToken and reset the activeCallback flag
    let refreshToken;
    let activeCallback;
    if (authInstance) {
        activeCallback = authInstance.isActiveCallback();
        authInstance.setActiveCallback(false);
        refreshToken = authInstance.refreshToken;
    }

    // Set up the authorization flow instance, except if there is an active callback.
    if (!activeCallback) {
        // Set up the auth flow instance
        if (variant) {
            authInstance = new flowClasses[flowName](variant);
        } else if (inputUsername && inputPassword) {
            authInstance = new flowClasses[flowName](inputUsername, inputPassword);
        } else {
            authInstance = new flowClasses[flowName]();
        }

        authInstance.refreshToken = refreshToken;
    }

    // Render the flow launch page
    res.render('launchedFlow', {
        data: flowsList,
        authFlow: flowData,
    });
});

app.get('/state', (req, res) => {
    const step = authInstance.currentStep;

    // For user-agent, we're parsing access token and id token on client side
    // So we're passing these in when we're retrieving the state. Not ideal?
    const newAccessToken = req.query.accessToken;
    if (newAccessToken) {
        authInstance.accessToken = newAccessToken;
    }
    const newIdToken = req.query.idToken;
    if (newIdToken) {
        authInstance.idToken = newIdToken;
    }

    const flowState = {
        step: step,
        baseURL: baseURL,
        clientId: clientId,
        clientSecret: clientSecret,
        callbackURL: callbackURL,
        authCode: authInstance.code,
        accessToken: authInstance.accessToken,
        refreshToken: authInstance.refreshToken,
        idToken: authInstance.idToken,
        request: authInstance.currentRequest,
        response: authInstance.currentResponse,
    };

    res.send(flowState);
});

app.get('/execute-step', async (req, res) => {
    let outcome;
    if (req.query.direction === 'next') {
        outcome = await authInstance.executeNextStep();
    } else if (req.query.direction === 'previous') {
        outcome = authInstance.returnToPreviousStep();
    }
    res.send(outcome);
});

/**
 * Username Password oAuth Flow. Gets launched when navigating to '/username-password'.
 * Sends username and password in the URL as free text to the token endpoint.
 */
app.post('/username-password', function (req, res) {
    // Instantiate Username-Password service and generate post request
    inputUsername = req.body.sfdcUsername;
    inputPassword = req.body.sfdcPassword;
    res.redirect('/launch/username-password');
});

/**
 * This method is called every time we poll the token endpoint to see if the device
 * was authorized. It only loads the page in case a response was received
 */
app.get('/devicePol', async (req, res) => {
    authInstance.setActiveCallback(true);

    await authInstance.pollTokenEndpoint();
    res.redirect('/launch/device');
});

/**
 * Handle OAuth callback from Salesforce and parse the result.
 * Result is parsed in oauthcallback.ejs.
 */
app.get('/services/oauth2/success', function (req, res) {
    let code = req.query.code;
    let returnedState = escape(req.query.state);
    let originalState = authInstance ? authInstance.state : undefined;

    console.debug('Callback received with code %s and state %s', code, returnedState);

    authInstance.setActiveCallback(true);
    authInstance.currentResponse = req.originalUrl;

    if (code) {
        // If an authorization code is returned, check the state and continue web-server flow.
        if (returnedState === originalState) {
            authInstance.code = code;
            res.redirect('/launch/web-server-client-secret');
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
        res.redirect('/launch/user-agent');
    }
});

app.get('/devicecallback', (req, res) => {
    res.render('deviceOAuth', {
        verification_uri: req.query.verification_uri,
        user_code: req.query.user_code,
        data: flowsList,
    });
});

/**
 * Log message to indicate on which port the application is running.
 */
app.listen(app.get('port'), function () {
    console.log('Express server listening on port ' + app.get('port'));
});

// Load files with private key and corresponding public certificate
const options = {
    key: fs.readFileSync('./key.pem', 'utf8'),
    cert: fs.readFileSync('./server.crt', 'utf8'),
};

// Create the server and log that it's up and running
https.createServer(options, app).listen(8081);
console.log('Server listening for HTTPS connections on port ', 8081);
