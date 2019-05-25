/**
 * Get URL parameters. Different logic for hash vs. regular.
 */
function getParameterList() {
    var message;

    if (window.location.hash) {
        message = decodeURIComponent(window.location.hash.substr(1));
    } else {
        message = decodeURIComponent(window.location.search.substr(1));
    }

    var params = message.split("&"), response = {};

    params.forEach(function(param) {
        var keyValue = param.split("=");
        response[keyValue[0]] = keyValue[1];
    });

    return response;
}

/**
 * Process the callback coming from the authorization endpoint with the access token (User-Agent)
 * @param {Map<String, String>} paramKeyValueMap 
 */
function processUserAgentCallback(paramKeyValueMap) {
    var apiVersion = "v45.0";
    var accessToken = paramKeyValueMap['access_token'];

    if (accessToken) {
        $.cookie("AccToken", accessToken);
        $.cookie("APIVer", apiVersion);
        $.cookie("InstURL", paramKeyValueMap['instance_url']);
        $.cookie("idURL", paramKeyValueMap['id']);

        strngBrks = paramKeyValueMap['id'].split("/");
        $.cookie("LoggeduserId", strngBrks[strngBrks.length - 1]);
        window.location = "Main";
    } else {
        $("#h2Message").html("AuthenticationError: No Token");
    }
}

/**
 * Process the callback coming from the authorization endpoint with the authorization code (Web Server)
 * @param {Map<String, String>} paramKeyValueMap 
 */
function processAuthorizationCodeCallback(paramKeyValueMap) {
    var access_code = paramKeyValueMap['code'];
    var state = paramKeyValueMap['state'];

    if (state.includes("webServer")) {
        //Its webserver flow so extract Token
        $("#h2Message").html("I am Webserver Flow");
        window.location = "webServerStep2?code=" + access_code + "&state=" + state;
    } else {
        $.cookie("AccToken", access_code);
        window.location = "Main";
    }
}

/**
 * Call this method on loading of the callback page
 */
function processCallback() {
    var paramKeyValueMap = getParameterList();
    console.log('Inside process callback'+paramKeyValueMap);
    if (window.location.hash) {
        processUserAgentCallback(paramKeyValueMap);
    } else if (paramKeyValueMap['code']) {
        processAuthorizationCodeCallback(paramKeyValueMap);
    } else {
        $("#h2Message").html("No access token in query string");
    }
}
