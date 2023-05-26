const { AuthService } = require('./auth');

var base64url = require('base64-url'),
    fetch = require('node-fetch');

class JwtService extends AuthService {
    constructor() {
        super();
        this.orderedCalls = [this.executeJwtBearerTokenFlow, this.performQuery];
    }

    /**
     * Create a JSON Web Token that is signed using the private key stored in 'key.pem'.
     * It first creates the Claims JSON and passes it to the signJwtClaims method.
     */
    generateSignedJwt() {
        var claims = {
            iss: this.clientId,
            sub: this.username,
            aud: this.getAudience(),
            exp: Math.floor(Date.now() / 1000) + 60 * 3, // valid for 3 minutes
        };

        return this.signJwtClaims(claims);
    }

    executeJwtBearerTokenFlow = async () => {
        // Set parameters for POST request
        const grantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        let endpointUrl = this.getTokenEndpoint();
        let token = this.generateSignedJwt();
        let paramBody = 'grant_type=' + base64url.escape(grantType) + '&assertion=' + token;

        // Create the current POST request based on the constructed body
        this.currentRequest = this.createPostRequest(endpointUrl, paramBody);
        this.redirect = false;

        // Use fetch to execute the POST request
        const response = await fetch(this.currentRequest.url, {
            method: this.currentRequest.method,
            headers: this.currentRequest.headers,
            body: this.currentRequest.body,
        });

        // Store the JSON response in the currentResponse variable
        this.currentResponse = await response.json();
        this.accessToken = this.currentResponse.access_token;
    };
}

exports.JwtService = JwtService;
