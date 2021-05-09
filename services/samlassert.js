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

        // Read assertion XML from file located at 'data/axiomSamlAssertion.xml'. Alternatively, copy-paste XML string below.
        const fileLocation = 'data/axiomSamlAssertion.xml';
        let assertionXml;
        try {
            assertionXml = fs.readFileSync(path.resolve(fileLocation), 'utf8');
        }
        // If exception, re-throw with more helpful message to be displayed to user
        catch(e) {
            console.log(e);
            throw new Error('Could not load Axiom SAML from '+fileLocation+'- check the instructions for this flow ensure the assertion file has been delpoyed');
        }
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
