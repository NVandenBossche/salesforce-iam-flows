var fs = require('fs'),
    path = require('path'),
    nJwt = require('njwt'),
    CryptoJS = require('crypto-js');

class AuthService {
    constructor() {
        this.clientId = process.env.CLIENT_ID;
        this.clientSecret = process.env.CLIENT_SECRET;
        this.callbackURL = process.env.CALLBACK_URL;
        this.baseURL = process.env.BASE_URL;
        this.username = process.env.USERNAME;
        this.persistTokensToFile = process.env.PERSIST === 'true';
        this.isSandbox = false;
        this.state = '';
        this.apiVersion = 'v45.0';
    }

    /**
     * Return the base URL for sending any HTTP requests to
     */
    getBaseUrl() {
        return this.isSandbox ? 'https://test.salesforce.com/' : this.baseURL;
    }

    /**
     * Return the audience for authorization requests
     */
    getAudience() {
        return this.isSandbox ? 'https://test.salesforce.com/' : 'https://login.salesforce.com';
    }

    /**
     * Return the Authorization Endpoint for the set base URL
     */
    getAuthorizeEndpoint() {
        return this.getBaseUrl() + '/services/oauth2/authorize';
    }

    /**
     * Return the Token Endpoint for the set base URL
     * @returns The token endpoint URL
     */
    getTokenEndpoint() {
        return this.getBaseUrl() + '/services/oauth2/token';
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

    // TODO: find a more elegant way of managing the callback. There are 3 options: show error, redirect to a new page, or show results page.
    processCallback(remoteBody) {
        // True if successful call
        let success = true;
        // Indicates whether there is a need to rerender the page with some parameters (device flow)
        let rerender = false;
        // Any headers that need to be sent for redirection
        let header;
        // Any parameters for a rerender are stored in the payload
        let payload;
        // Contains either an error message, rerender target or refresh token
        let response;

        // Retrieve the response and store in JSON object
        let sfdcResponse = JSON.parse(remoteBody);

        // Parse specific parts of the response and store in variables
        let identityUrl = sfdcResponse.id;
        let issuedAt = sfdcResponse.issued_at;
        let idToken = sfdcResponse.id_token;
        let accessToken = sfdcResponse.access_token;
        let verificationUri = sfdcResponse.verification_uri;
        let userCode = sfdcResponse.user_code;
        let deviceCode = sfdcResponse.device_code;
        let interval = sfdcResponse.interval;

        console.log('AT: ' + accessToken);

        // If identity URL is specified, check its signature based on identity URL and 'issued at'
        if (identityUrl && issuedAt) {
            // Create SHA-256 hash of identity URL and 'issued at' based on client secret
            let hash = CryptoJS.HmacSHA256(identityUrl + issuedAt, this.clientSecret);
            let hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

            // Show error if base64 encoded hash doesn't match with the signature in the response
            if (hashInBase64 != sfdcResponse.signature) {
                success = false;
                response = 'Signature not correct - Identity cannot be confirmed';
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

        // For correct (or blank) signatures, check in which of the 3 scenarios we are
        if (success) {
            if (accessToken) {
                // If access token is present, we redirect to queryresult page with some cookies.
                let refreshToken;

                if (sfdcResponse.refresh_token) {
                    refreshToken = sfdcResponse.refresh_token;
                }

                header = {
                    Location: 'queryresult',
                    'Set-Cookie': [
                        'AccToken=' + accessToken,
                        'APIVer=' + this.apiVersion,
                        'InstURL=' + sfdcResponse.instance_url,
                        'idURL=' + sfdcResponse.id,
                    ],
                };

                response = refreshToken;
            } else if (verificationUri) {
                // If verification URI is present, we are in device flow and need to keep polling
                rerender = true;
                response = 'deviceOAuth';
                payload = {
                    verification_uri: verificationUri,
                    user_code: userCode,
                    device_code: deviceCode,
                    isSandbox: this.isSandbox,
                    interval: interval,
                };
            } else {
                // If no access token or verification URI is present, something went wrong
                success = false;
                response = 'An error occurred. For more details, see the response from Salesforce: ' + remoteBody;
            }
        }
        return { success, rerender, header, payload, response };
    }
}

exports.AuthService = AuthService;
