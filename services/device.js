const { AuthService } = require('./auth');

var fetch = require('node-fetch');

class DeviceService extends AuthService {
    #deviceCode;
    #userCode;
    #interval;
    #verificationUrl;

    constructor() {
        super();
        this.orderedCalls = [this.executeDeviceFlow, this.generateCallbackRequest, this.performQuery];
    }

    executeDeviceFlow = async () => {
        // Define parameters
        const responseType = 'device_code';
        let endpointUrl = this.getTokenEndpoint();
        let paramBody = 'client_id=' + this.clientId + '&response_type=' + responseType;

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

        // Parse the output
        this.#deviceCode = this.currentResponse.device_code;
        this.#userCode = this.currentResponse.user_code;
        this.#interval = this.currentResponse.interval;
        this.#verificationUrl = this.currentResponse.verification_uri;
    };

    generatePollingRequest() {
        // Retrieve query parameters for further processing
        const grantType = 'device';

        // Set parameters for POST request
        let endpointUrl = this.getTokenEndpoint();
        let paramBody = 'client_id=' + this.clientId + '&grant_type=' + grantType + '&code=' + this.#deviceCode;

        return this.createPostRequest(endpointUrl, paramBody);
    }

    generateCallbackRequest = async () => {
        this.redirect = true;
        this.currentRequest =
            '/devicecallback?' + 'verification_uri=' + this.#verificationUrl + '&user_code=' + this.#userCode;
    };

    // TODO: Add timeout after x minutes
    pollTokenEndpoint = async () => {
        let postRequest = this.generatePollingRequest();
        let interval = this.#interval;
        let pollResponse;

        while (true) {
            pollResponse = await this.postToEndpoint(postRequest);
            if (!pollResponse.error) {
                break;
            }
            await this.sleep(interval * 1000);
        }

        this.currentRequest = postRequest;
        this.currentResponse = pollResponse;
        this.accessToken = pollResponse.access_token;
        this.refreshToken = pollResponse.refresh_token;
        this.idToken = pollResponse.id_token;
        this.redirect = false;

        return pollResponse;
    };

    // Post to the token endpoint and return response
    postToEndpoint = async (postRequest) => {
        // Use fetch to execute the POST request
        const response = await fetch(postRequest.url, {
            method: postRequest.method,
            headers: postRequest.headers,
            body: postRequest.body,
        });
        const jsonResponse = await response.json();

        return jsonResponse;
    };

    // Sleep function to wait specified amount of ms
    sleep = async (timeInMs) => {
        await new Promise((resolve) => {
            return setTimeout(resolve, timeInMs);
        });
    };
}

exports.DeviceService = DeviceService;
