const { AuthService } = require('./auth');

class UserAgentService extends AuthService {
    constructor() {
        super();
        this.orderedCalls = [this.executeUserAgentFlow, this.performQuery];
    }

    executeUserAgentFlow = async () => {
        // Set response type and get url of authorization endpoint
        let responseType = 'token';
        let endpointUrl = this.getAuthorizeEndpoint();

        // Construct the url for the user agent flow, including parameters in url
        let authorizationUrl =
            endpointUrl +
            '?client_id=' +
            this.clientId +
            '&redirect_uri=' +
            this.callbackURL +
            '&response_type=' +
            responseType;

        // Set the currentRequest with redirect = true to indicate to the front-end that a redirect is needed.
        this.currentRequest = authorizationUrl;
        this.redirect = true;
    };
}

exports.UserAgentService = UserAgentService;
