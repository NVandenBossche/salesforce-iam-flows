var fs = require('fs'),
    path = require('path'),
    nJwt = require('njwt'),
    jsforce = require('jsforce');

class AuthService {
    orderedCalls;
    currentStep = 1;
    currentRequest;
    currentResponse;
    redirect;
    accessToken;
    refreshToken;
    #activeCallback = false;
    state = '';

    constructor() {
        this.clientId = process.env.CLIENT_ID;
        this.clientSecret = process.env.CLIENT_SECRET;
        this.callbackURL = process.env.CALLBACK_URL;
        this.baseURL = process.env.BASE_URL;
        this.username = process.env.USERNAME;
        this.persistTokensToFile = process.env.PERSIST === 'true';
        this.apiVersion = process.env.API_VERSION;
    }

    /**
     * Return the audience for authorization requests
     */
    getAudience() {
        let isSandbox = this.baseURL.includes('.sandbox.my.salesforce.com');
        return isSandbox ? 'https://test.salesforce.com/' : 'https://login.salesforce.com';
    }

    /**
     * Return the Authorization Endpoint for the set base URL
     */
    getAuthorizeEndpoint() {
        return this.baseURL + '/services/oauth2/authorize';
    }

    /**
     * Return the Token Endpoint for the set base URL
     * @returns The token endpoint URL
     */
    getTokenEndpoint() {
        return this.baseURL + '/services/oauth2/token';
    }

    /**
     * Creates a HTTP POST request JSON object that can be passed along to the Express "request".
     * @param {String} endpointUrl The url of the endpoint (authorization or token).
     * @param {String} body The parameters to be passed to the endpoint as URL parameters (key1=value1&key2=value2&...).
     * @returns JSON object containing information needed for sending the POST request.
     */
    createPostRequest(endpointUrl, body) {
        return {
            method: 'POST',
            url: endpointUrl,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body,
        };
    }

    /**
     * Takes JSON formatted claims, creates a header for them, signs it with the
     * private key stored in 'key.pem' and base64 encodes the concatenation
     * "header.claims.signature".
     * @param {String} claims A JSON representation of the JWT claims containing
     *  issuer (client ID), subject (Salesforce username), audience (login/test)
     *  and expiration.
     */
    signJwtClaims(claims) {
        // Read private key into memory
        let privateKey = fs.readFileSync(path.resolve('key.pem'));

        // Leverage njwt library to create JWT token based on claims and private key
        let jwtToken = nJwt.create(claims, privateKey, 'RS256');

        // Return base64 version of the JWT token
        return jwtToken.compact();
    }

    /**
     * Performs a query against the Salesforce instance using the access token.
     */
    performQuery = async () => {
        // Set up a JSforce connection
        const connection = new jsforce.Connection({
            instanceUrl: this.baseURL,
            accessToken: this.accessToken,
            version: this.apiVersion,
        });

        // Define the query and perform the query
        const query = 'Select Id, Name From Account LIMIT 10';
        const queryResponse = await connection.query(query);

        // Set the current request and response
        this.currentRequest = [this.baseURL, 'services/data', 'v' + this.apiVersion, 'query?q=' + query].join('/');
        this.currentResponse = queryResponse;
        this.redirect = false;
    };

    /**
     * Executes the next step in the flow. The order of the steps is defined in the orderedCalls function array.
     *
     * @returns A JSON object containing the request, response, and whether a redirect is required.
     */
    async executeNextStep() {
        // Retrieve and execute the function based on the step number
        let functionToExecute = this.orderedCalls[this.currentStep - 1];
        this.currentStep++;
        await functionToExecute();

        // The function will set the currentRequest, currentResponse and redirect parameters. Then return them.
        return {
            request: this.currentRequest,
            response: this.currentResponse,
            redirect: this.redirect,
        };
    }

    returnToPreviousStep() {
        this.currentStep--;
        return true;
    }

    setActiveCallback(activeCallback) {
        this.#activeCallback = activeCallback;
    }

    isActiveCallback() {
        return this.#activeCallback;
    }
}

exports.AuthService = AuthService;
