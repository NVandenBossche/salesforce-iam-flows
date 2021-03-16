const { AuthService } = require('./auth');

var crypto = require('crypto'),
    CryptoJS = require('crypto-js'),
    base64url = require('base64-url');

class WebServerService extends AuthService {
    constructor(isSandbox, webServerType) {
        super(isSandbox);
        this.webServerType = webServerType;
        this.codeVerifier = this.generateCodeVerifier();
        this.codeChallenge = this.generateCodeChallenge(this.codeVerifier);
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
     * Function that generates a cryptographically random code verifier
     * @returns Cryptographically random code verifier
     */
    generateCodeVerifier() {
        return crypto.randomBytes(128).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
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

        console.log('---' + this.webServerType + '---');

        // Add additional parameters in case of 'Client secret' or 'Client assertion' flow
        if (this.webServerType === 'secret') {
            paramBody += '&client_secret=' + this.clientSecret;
        } else if (this.webServerType === 'assertion') {
            console.log('Web server type: assertion');
            paramBody += '&client_assertion=' + this.createClientAssertion();
            paramBody += '&client_assertion_type=' + 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
        }

        // Create the full POST request with all required parameters
        return this.createPostRequest(endpointUrl, paramBody);
    }
}

exports.WebServerService = WebServerService;
