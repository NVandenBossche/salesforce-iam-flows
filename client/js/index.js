// Clear all cookies upon the loading of the page
function clearAllCookies() {
    Cookies.remove('AccToken');
    Cookies.remove('APIVer');
    Cookies.remove('InstURL');
    Cookies.remove('idURL');
    Cookies.remove('LoggeduserId');
}

function onload() {
    clearAllCookies();
}

window.onload = onload;
