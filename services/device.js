const { AuthService } = require('./auth');

var request = require('request');

class DeviceService extends AuthService {
    constructor(isSandbox) {
        super(isSandbox);
    }

    generateDeviceRequest() {
        // Define parameters
        const responseType = 'device_code';
        let endpointUrl = this.getTokenEndpoint();
        let paramBody = 'client_id=' + this.clientId + '&response_type=' + responseType;

        // Create post request to be sent to the token endpoint
        return this.createPostRequest(endpointUrl, paramBody);
    }

    generatePollingRequest(deviceCode) {
        // Retrieve query parameters for further processing
        const grantType = 'device';

        // Set parameters for POST request
        let endpointUrl = this.getTokenEndpoint();
        let paramBody = 'client_id=' + this.clientId + '&grant_type=' + grantType + '&code=' + deviceCode;

        return this.createPostRequest(endpointUrl, paramBody);
    }

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
            redirect = {}
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
    pollContinually() {
        let postRequest = this.generatePollingRequest(this.deviceCode);
        let interval = this.interval;
        let deviceResponse;
        let _this = this;

        return new Promise((resolve, reject) => {
            function pollSalesforceForAuthorization() {
                request(postRequest, function (error, remoteResponse, remoteBody) {
                    // Handle error or process response
                    if (error) {
                        reject(JSON.stringify(error));
                    } else {
                        console.log('RemoteBody: ' + remoteBody);
                        deviceResponse = _this.parseResults(remoteBody);
                        keepPolling();
                    }
                });
            }

            function keepPolling() {
                if (deviceResponse && deviceResponse.accessTokenHeader) {
                    resolve(deviceResponse);
                } else {
                    setTimeout(pollSalesforceForAuthorization, interval * 1000);
                }
            }

            keepPolling();
        });
    }
}

exports.DeviceService = DeviceService;
