/**
 * Get URL parameters. Different logic for hash vs. regular.
 */
function getParameterList() {
    let message = window.location.hash.substr(1);
    let parameters = message.split('&');
    let response = {};

    parameters.forEach(function (parameter) {
        let keyValue = parameter.split('=');
        response[keyValue[0]] = keyValue[1];
    });

    return response;
}

/**
 * Process the callback coming from the authorization endpoint with the access token (User-Agent)
 * @param {Map<String, String>} paramKeyValueMap
 */
function processUserAgentCallback(paramKeyValueMap) {
    let apiVersion = 'v45.0';
    let accessToken = decodeURIComponent(paramKeyValueMap['access_token']);
    let instanceUrl = decodeURIComponent(paramKeyValueMap['instance_url']);
    let idUrl = decodeURIComponent(paramKeyValueMap['id']);

    if (accessToken) {
        $.cookie('AccToken', accessToken);
        $.cookie('APIVer', apiVersion);
        $.cookie('InstURL', instanceUrl);
        $.cookie('idURL', idUrl);

        userId = paramKeyValueMap['id'].split('/');
        $.cookie('LoggeduserId', userId[userId.length - 1]);
        window.location = 'queryresult';
    } else {
        $('#h2Message').html('AuthenticationError: No Token');
    }
}

/**
 * Call this method on loading of the callback page
 */
function processCallback() {
    if (window.location.hash) {
        let paramKeyValueMap = getParameterList();
        processUserAgentCallback(paramKeyValueMap);
    } else {
        $('#h2Message').html('No access token in query string');
    }
}
