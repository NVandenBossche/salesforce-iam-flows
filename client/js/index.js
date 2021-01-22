// Clear all cookies upon the loading of the page
function clearAllCookies() {
    $.cookie('AccToken', '');
    $.cookie('APIVer', '');
    $.cookie('InstURL', '');
    $.cookie('idURL', '');
    $.cookie('LoggeduserId', '');
}

// Single method for launching any of the flows
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
