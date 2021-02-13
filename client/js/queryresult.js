// Initialize global variables and instantiate the Salesforce communication client based on cookies
var apiCount = 0,
    instanceUrl = $.cookie('InstURL'),
    apiVersion = $.cookie('APIVer'),
    accessToken = $.cookie('AccToken'),
    idUrl = $.cookie('idURL'),
    proxyURL = window.location.origin + '/proxy/',
    clientId = '',
    client = new forcetk.Client(clientId, instanceUrl, proxyURL);

function onload() {
    // Set the access token for the client's session, display the user info, and execute the query
    if (accessToken && apiVersion && instanceUrl) {
        client.setSessionToken(accessToken, apiVersion, instanceUrl);
        getLoggedInUserInfo();
        executeQuery();
    } else {
        $('#result').html(
            'Some issue occurred during authentication. Please contact admin or try again by <a href="index.html">navigating here</a>.'
        );
    }

    // Execute the query and display results if the user presses the 'Enter' button on their keyboard while the query box has focus.
    $('#Query-to-execute').keypress(function (e) {
        let key = e.which;

        // 13 is the key code for the 'Enter' key
        if (key == 13) {
            executeQuery();
        }
    });
}

// Retrieve details of the logged in user and display their name
function getLoggedInUserInfo() {
    let requestPayLoad = '',
        retry = true;

    client.ajax(
        idUrl,
        function (data) {
            let nameOfUser = data.display_name;
            $('#loggedInUser').html(nameOfUser);
        },
        function (error) {
            console.log(error);
        },
        'GET',
        requestPayLoad,
        retry
    );
}

// Execute the query that's entered in the text box
function executeQuery() {
    // Check if the user already has a session. If not, display error. If yes, display the result.
    if (!client.sessionId) {
        $('#result').html('You are not authenticated. Please login first.');
    } else {
        let queryToExecute = $('#Query-to-execute').val();

        client.query(
            queryToExecute,
            function (data) {
                let replacer = null,
                    whitespace = 4;
                $('#result').html(JSON.stringify(data, replacer, whitespace));
            },
            function (error) {
                $('#result').html('Error: ' + JSON.stringify(error));
            }
        );
    }
}

// Count the number of API calls since this page was loaded (just a gimmick)
function addAPICount() {
    apiCount++;
    $('#apiCount').text(apiCount);
}
