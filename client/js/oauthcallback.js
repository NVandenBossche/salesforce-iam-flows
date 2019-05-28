/**
 * Get URL parameters. Different logic for hash vs. regular.
 */
function getParameterList() {
    var message;

    if (window.location.hash) {
        message = window.location.hash.substr(1);
    } else {
        message = window.location.search.substr(1);
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
    var accessToken = decodeURIComponent(paramKeyValueMap['access_token']);
    var instanceUrl = decodeURIComponent(paramKeyValueMap['instance_url']);
    var idUrl = decodeURIComponent(paramKeyValueMap['id']);

    if (accessToken) {
        $.cookie("AccToken", accessToken);
        $.cookie("APIVer", apiVersion);
        $.cookie("InstURL", instanceUrl);
        $.cookie("idURL", idUrl);

        strngBrks = paramKeyValueMap['id'].split("/");
        $.cookie("LoggeduserId", strngBrks[strngBrks.length - 1]);
        window.location = "queryresult";
    } else {
        $("#h2Message").html("AuthenticationError: No Token");
    }
}

/**
 * Process the callback coming from the authorization endpoint with the authorization code (Web Server)
 * @param {Map<String, String>} paramKeyValueMap 
 */
function processAuthorizationCodeCallback(paramKeyValueMap) {
    if(returnedState == originalState) {
        if (returnedState.includes("webServer")) {
            //Its webserver flow so extract Token
            $("#h2Message").html("I am Webserver Flow");
            window.location = "webServerStep2?code=" + code;
        } else {
            $.cookie("AccToken", access_code);
            window.location = "queryresult";
        }
    } else {
        $("#h2Message").html("State changed --> Cross App / Site Request Forgery detected!");
    }
}

/**
 * Call this method on loading of the callback page
 */
function processCallback() {
    var paramKeyValueMap = getParameterList();
    if (window.location.hash) {
        processUserAgentCallback(paramKeyValueMap);
    } else if (paramKeyValueMap['code']) {
        processAuthorizationCodeCallback(paramKeyValueMap);
    } else {
        $("#h2Message").html("No access token in query string");
    }
}
