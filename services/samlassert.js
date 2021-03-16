const { AuthService } = require('./auth');

var fs = require('fs'),
    path = require('path');

class SamlAssertService extends AuthService {
    constructor(isSandbox) {
        super(isSandbox);
    }

    generateSamlAssertRequest() {
        // Set parameters for the SAML request body
        const assertionType = 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser';
        let endpointUrl = this.getTokenEndpoint();

        // Read assertion XML from file located at 'data/axiomSamlAssertion.xml'. Alternatively, copy-paste XML string below and assign to variable.
        let assertionXml = fs.readFileSync(path.resolve('data/axiomSamlAssertion.xml'), 'utf8');
        let base64AssertionXml = Buffer.from(assertionXml).toString('base64');

        // Construct the request body containing grant type, assertion type and assertion. All should be URL encoded.
        let samlParamBody =
            'grant_type=' +
            encodeURIComponent('assertion') +
            '&assertion_type=' +
            encodeURIComponent(assertionType) +
            '&assertion=' +
            encodeURIComponent(base64AssertionXml);

        return this.createPostRequest(endpointUrl, samlParamBody);
    }
}

exports.SamlAssertService = SamlAssertService;
