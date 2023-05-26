const { AuthService } = require('./auth');

const base64url = require('base64-url'),
    fetch = require('node-fetch');

class RefreshService extends AuthService {
    constructor() {
        super();
        this.orderedCalls = [this.executeRefreshTokenFlow, this.performQuery];
    }

    executeRefreshTokenFlow = async () => {
        // Set parameters for POST request
        const grantType = 'refresh_token';
        let endpointUrl = this.getTokenEndpoint();
        let paramBody =
            'grant_type=' +
            base64url.escape(grantType) +
            '&refresh_token=' +
            this.refreshToken +
            '&client_id=' +
            this.clientId;

        // Create the current POST request based on the constructed body
        this.currentRequest = this.createPostRequest(endpointUrl, paramBody);

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

exports.RefreshService = RefreshService;
