const { AuthService } = require('./auth');

class UsernamePasswordService extends AuthService {
    constructor(isSandbox) {
        super(isSandbox);
    }

    generateUsernamePasswordRequest(username, password) {
        // Construct parameters for POST request
        const grantType = 'password';
        let endpointUrl = this.getTokenEndpoint();

        // Create body for POST request
        let paramBody =
            'client_id=' +
            this.clientId +
            '&grant_type=' +
            grantType +
            '&client_secret=' +
            this.clientSecret +
            '&username=' +
            username +
            '&password=' +
            encodeURIComponent(password); // Encode in case password contains special characters

        // Set the request parameters for the token endpoint
        return this.createPostRequest(endpointUrl, paramBody);
    }
}

exports.UsernamePasswordService = UsernamePasswordService;
