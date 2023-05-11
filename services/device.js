const { AuthService } = require('./auth');

var request = require('request'),
    fetch = require('node-fetch');

class DeviceService extends AuthService {
    #deviceCode;
    #userCode;
    #interval;
    #verificationUrl;

    constructor() {
        super();
        this.orderedCalls = [this.generateDeviceRequest, this.generateCallbackRequest, this.performQuery];
    }

    generateDeviceRequest = async () => {
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

    generatePollingRequest(deviceCode) {
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

    processCallback(remoteBody) {
        // Return value for redirect
        let redirect;
        let error;

        // Parse response for device code, interval, verification URI and user code
        let salesforceResponse = JSON.parse(remoteBody);
        this.deviceCode = salesforceResponse.device_code;
        this.interval = salesforceResponse.interval;
        let verificationUri = salesforceResponse.verification_uri;
        let userCode = salesforceResponse.user_code;

        if (verificationUri) {
            // If verification URI is present, we are in device flow and need to keep polling
            redirect = {};
            redirect.location = 'deviceOAuth';
            redirect.payload = {
                verification_uri: verificationUri,
                user_code: userCode,
            };
        } else {
            // If no verification URI is present, something went wrong
            error = 'An error occurred. For more details, see the response from Salesforce: ' + remoteBody;
        }

        return { error, undefined, undefined, redirect };
    }

    // TODO: Add timeout after x minutes
    pollContinually = async () => {
        let postRequest = this.generatePollingRequest(this.#deviceCode);
        let interval = this.#interval;
        let pollResponse;

        while (true) {
            pollResponse = await this.singlePoll(postRequest);
            if (!pollResponse.error) {
                break;
            }
            await this.sleep(interval * 1000);
        }

        console.log('Store current request:');
        console.log(postRequest);
        this.currentRequest = postRequest;
        console.log('Store current response:');
        console.log(pollResponse);
        this.currentResponse = pollResponse;
        this.accessToken = pollResponse.access_token;
        this.refreshToken = pollResponse.refresh_token;
        this.redirect = false;

        return pollResponse;
    };

    singlePoll = async (postRequest) => {
        // Use fetch to execute the POST request
        const response = await fetch(postRequest.url, {
            method: postRequest.method,
            headers: postRequest.headers,
            body: postRequest.body,
        });
        const jsonResponse = await response.json();

        return jsonResponse;
    };

    sleep = async (milliseconds) => {
        await new Promise((resolve) => {
            return setTimeout(resolve, milliseconds);
        });
    };
}

exports.DeviceService = DeviceService;
