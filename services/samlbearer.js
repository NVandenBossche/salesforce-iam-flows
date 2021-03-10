const { AuthService } = require('./auth');

var saml = require('saml').Saml20,
    fs = require('fs'),
    path = require('path'),
    base64url = require('base64-url');

class SamlBearerService extends AuthService {
    constructor(isSandbox) {
        super(isSandbox);
    }

    /**
     * Create a SAML Bearer Token that is signed using the private key stored in 'key.pem'.
     * It first creates the list of SAML claims and passes it to the create method of the saml library.
     * @returns {String} The signed SAML Bearer token in utf-8 encoding.
     */
    getSignedSamlToken() {
        // Retrieve private key and server certificate
        let privateKey = fs.readFileSync(path.resolve('key.pem'));
        let publicCert = fs.readFileSync(path.resolve('server.crt'));

        // Set claims / options for SAML Bearer token. All of these are required for Salesforce.
        let samlClaims = {
            cert: publicCert,
            key: privateKey,
            issuer: this.clientId,
            lifetimeInSeconds: 600,
            audiences: this.getAudience(),
            nameIdentifier: this.username,
        };

        // Return the SAML token which is signed with the private key (not encrypted)
        return saml.create(samlClaims);
    }

    generateSamlBearerRequest() {
        // Set parameters for the SAML request body
        const assertionType = 'urn:ietf:params:oauth:grant-type:saml2-bearer';
        let token = this.getSignedSamlToken();
        let base64SignedSamlToken = base64url.encode(token);

        // If persist option is set to true, persist the SAML bearer token and its base64 encoding to file
        if (this.persistTokensToFile) {
            fs.writeFile(path.resolve('data/samlBearer.xml'), token);
            fs.writeFile(path.resolve('data/samlBase64.txt'), base64SignedSamlToken);
        }

        // Determine the endpoint URL depending on whether this needs to be executed on sandbox or production
        let endpointUrl = this.getTokenEndpoint();

        // Set the body of the POST request by defining the grant_type and assertion parameters
        let paramBody = 'grant_type=' + assertionType + '&assertion=' + base64SignedSamlToken;

        // Return the POST request created based on the endpoint and body
        return this.createPostRequest(endpointUrl, paramBody);
    }
}

exports.SamlBearerService = SamlBearerService;
