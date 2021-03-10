const { AuthService } = require('./auth');

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
}

exports.DeviceService = DeviceService;
