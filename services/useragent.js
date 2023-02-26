const { AuthService } = require('./auth');

class UserAgentService extends AuthService {
    constructor() {
        super();
    }

    generateUserAgentRequest() {
        // Set response type and get url of authorization endpoint
        let responseType = 'token';
        let endpointUrl = this.getAuthorizeEndpoint();

        // Construct the url for the user agent flow, including parameters in url
        return (
            endpointUrl +
            '?client_id=' +
            this.clientId +
            '&redirect_uri=' +
            this.callbackURL +
            '&response_type=' +
            responseType
        );
    }
}

exports.UserAgentService = UserAgentService;
