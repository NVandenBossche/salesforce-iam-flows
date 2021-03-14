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
        let salesforceResponse = JSON.parse(remoteBody);

        this.deviceCode = salesforceResponse.device_code;
        this.interval = salesforceResponse.interval;

        return super.processCallback(remoteBody);
    }

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
                if (!(deviceResponse && deviceResponse.success && deviceResponse.header)) {
                    setTimeout(pollSalesforceForAuthorization, interval * 1000);
                } else {
                    resolve(deviceResponse);
                }
            }

            keepPolling();
        });
    }
}

exports.DeviceService = DeviceService;
