const { AuthService } = require('./auth');

var crypto = require('crypto'),
    CryptoJS = require('crypto-js'),
    request = require('request'),
    base64url = require('base64-url');

class WebServerService extends AuthService {
    constructor(isSandbox, webServerType) {
        super(isSandbox);
        this.webServerType = webServerType;
        this.codeVerifier = this.generateCodeVerifier();
        this.codeChallenge = this.generateCodeChallenge(this.codeVerifier);
    }

    generateAuthorizationRequest() {
        // Set parameter values for retrieving authorization code
        let responseType = 'code';
        let scope = 'full%20refresh_token';
        let endpointUrl = this.getAuthorizeEndpoint();

        // Create a state to prevent CSRF
        this.state = base64url.escape(crypto.randomBytes(32).toString('base64'));

        // Generate the url to request the authorization code, including parameters
        let authorizationUrl =
            endpointUrl +
            '?client_id=' +
            this.clientId +
            '&redirect_uri=' +
            encodeURI(this.callbackURL) +
            '&response_type=' +
            responseType +
            '&state=' +
            this.state +
            '&scope=' +
            scope +
            '&code_challenge=' +
            this.codeChallenge;

        return authorizationUrl;
    }

    /**
     * Step 2 Web Server Flow - Get access token using authorization code.
     * Gets launched as part of the callback actions from the first step of the web server flow.
     * This is the second step in the flow where the access token is retrieved by passing the previously
     * obtained authorization code to the token endpoint.
     */
    generateTokenRequest(code) {
        // Set parameter values for retrieving access token
        let grantType = 'authorization_code';
        let endpointUrl = this.getTokenEndpoint();

        // Set the different parameters in the body of the post request
        let paramBody =
            'client_id=' +
            this.clientId +
            '&redirect_uri=' +
            encodeURI(this.callbackURL) +
            '&grant_type=' +
            grantType +
            '&code=' +
            code +
            '&code_verifier=' +
            this.codeVerifier;

        // Add additional parameters in case of 'Client secret' or 'Client assertion' flow
        if (this.webserverType == 'secret') {
            paramBody += '&client_secret=' + this.clientSecret;
        } else if (this.webserverType == 'assertion') {
            paramBody += '&client_assertion=' + this.createClientAssertion();
            paramBody += '&client_assertion_type=' + 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        }

        // Create the full POST request with all required parameters
        return this.createPostRequest(endpointUrl, paramBody);
    }

    /**
     * Function that generates a cryptographically random code verifier
     * @returns Cryptographically random code verifier
     */
    generateCodeVerifier() {
        return crypto.randomBytes(128).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }

    /**
     * Function that hashes the code verifier and encodes it into base64URL
     * @param {String} verifier The code verifier string. This string should be long enough to be secure.
     * @returns Code challenge based on provided verifier
     */
    generateCodeChallenge(verifier) {
        return CryptoJS.SHA256(verifier)
            .toString(CryptoJS.enc.Base64)
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
    }

    /**
     * Create a JWT client assertion
     * @returns JWT client assertion
     */
    createClientAssertion() {
        let assertionData = {
            iss: this.clientId,
            sub: this.clientId,
            aud: this.getTokenEndpoint(),
            exp: Math.floor(new Date() / 1000) + 60 * 3,
        };

        return this.signJwtClaims(assertionData);
    }

    processCallback(remoteBody) {
        // Initialize return values
        let success = true;
        let header;
        let response;

        // Retrieve the response and store in JSON object
        let sfdcResponse = JSON.parse(remoteBody);

        // Parse specific parts of the response and store in variables
        let identityUrl = sfdcResponse.id;
        let issuedAt = sfdcResponse.issued_at;
        let idToken = sfdcResponse.id_token;
        let accessToken = sfdcResponse.access_token;

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

        // In case no error and signature checks out, AND there is an access token present, store refresh token in global state and redirect to query page
        if (success && accessToken) {
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
        } else if (success) {
            success = false;
            response = 'An error occurred. For more details, see the response from Salesforce: ' + remoteBody;
        }
        return { success, header, response };
    }
}

exports.WebServerService = WebServerService;
