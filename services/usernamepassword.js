const { AuthService } = require('./auth');

const fetch = require('node-fetch');

class UsernamePasswordService extends AuthService {
    #username;
    #password;

    constructor(username, password) {
        super();
        this.orderedCalls = [this.executeUsernamePasswordFlow, this.performQuery];
        this.#username = username;
        this.#password = password;
    }

    executeUsernamePasswordFlow = async () => {
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
            this.#username +
            '&password=' +
            encodeURIComponent(this.#password); // Encode in case password contains special characters

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

exports.UsernamePasswordService = UsernamePasswordService;
