// Clear all cookies upon the loading of the page
function clearAllCookies() {
    Cookies.remove('AccToken');
    Cookies.remove('APIVer');
    Cookies.remove('InstURL');
    Cookies.remove('idURL');
    Cookies.remove('LoggeduserId');
}

// Single method for launching any of the flows
// TODO: replace this method by just calling the Node resource.
// Type is being replaced, sandbox is not relevant because we have the ENV setting on BASE_URL.
function launchFlow(flowName, isSandbox, type) {
    // Initialize the redirect URL
    let newLocation = flowName + '?isSandbox=' + isSandbox;

    // Add parameters to the URL where needed
    if (type) {
        newLocation += '&type=' + type;
    }

    window.location = newLocation;
}

function onload() {
    clearAllCookies();
}

window.onload = onload;
