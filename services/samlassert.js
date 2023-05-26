const { AuthService } = require('./auth');

var fs = require('fs'),
    path = require('path'),
    fetch = require('node-fetch');

class SamlAssertService extends AuthService {
    constructor() {
        super();
        this.orderedCalls = [this.executeSamlAssertionFlow, this.performQuery];
    }

    executeSamlAssertionFlow = async () => {
        // Set parameters for the SAML request body
        const assertionType = 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:browser';
        let endpointUrl = this.getTokenEndpoint();

        // Read assertion XML from file located at 'data/axiomSamlAssertion.xml'. Alternatively, copy-paste XML string below.
        const fileLocation = 'data/axiomSamlAssertion.xml';
        let assertionXml;
        try {
            assertionXml = fs.readFileSync(path.resolve(fileLocation), 'utf8');
        } catch (e) {
            // If exception, re-throw with more helpful message to be displayed to user
            throw new Error(
                'Could not load Axiom SAML from ' +
                    fileLocation +
                    '- check the instructions for this flow ensure the assertion file has been delpoyed'
            );
        }
        let base64AssertionXml = Buffer.from(assertionXml).toString('base64');

        // Construct the request body containing grant type, assertion type and assertion. All should be URL encoded.
        let paramBody =
            'grant_type=' +
            encodeURIComponent('assertion') +
            '&assertion_type=' +
            encodeURIComponent(assertionType) +
            '&assertion=' +
            encodeURIComponent(base64AssertionXml);

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

exports.SamlAssertService = SamlAssertService;
