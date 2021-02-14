class AuthService {
    constructor() {
        this.clientId = process.env.CLIENT_ID;
        this.clientSecret = process.env.CLIENT_SECRET;
        this.callbackURL = process.env.CALLBACK_URL;
        this.baseURL = process.env.BASE_URL;
        this.username = process.env.USERNAME;
        this.persistTokensToFile = process.env.PERSIST === 'true';
        this.isSandbox = false;
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
}

exports.AuthService = AuthService;
