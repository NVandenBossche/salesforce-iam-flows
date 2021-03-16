const { AuthService } = require('./auth');

var base64url = require('base64-url');

class RefreshService extends AuthService {
    constructor(isSandbox) {
        super(isSandbox);
    }

    generateRefreshRequest(refreshToken) {
        // Set parameters for POST request
        const grantType = 'refresh_token';
        let endpointUrl = this.getTokenEndpoint();
        let paramBody =
            'grant_type=' +
            base64url.escape(grantType) +
            '&refresh_token=' +
            refreshToken +
            '&client_id=' +
            this.clientId;

        // Create the POST request
        return this.createPostRequest(endpointUrl, paramBody);
    }
}

exports.RefreshService = RefreshService;
