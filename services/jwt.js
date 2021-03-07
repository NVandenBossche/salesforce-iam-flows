const { AuthService } = require('./auth');

var base64url = require('base64-url');

class JwtService extends AuthService {
    constructor(isSandbox) {
        super(isSandbox);
    }

    /**
     * Create a JSON Web Token that is signed using the private key stored in 'key.pem'.
     * It first creates the Claims JSON and passes it to the signJwtClaims method.
     */
    getSignedJwt() {
        var claims = {
            iss: this.clientId,
            sub: this.username,
            aud: this.getAudience(),
            exp: Math.floor(Date.now() / 1000) + 60 * 3, // valid for 3 minutes
        };

        return this.signJwtClaims(claims);
    }

    generateJwtRequest() {
        // Set parameters for POST request
        const grantType = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        let endpointUrl = this.getTokenEndpoint();
        let token = this.getSignedJwt();
        let paramBody = 'grant_type=' + base64url.escape(grantType) + '&assertion=' + token;

        // Construct POST request based on body and endpoint
        return this.createPostRequest(endpointUrl, paramBody);
    }
}

exports.JwtService = JwtService;
