// Initialize global variables and instantiate the Salesforce communication client based on cookies
var apiCount = 0,
    instanceUrl = Cookies.get('InstURL'),
    apiVersion = Cookies.get('APIVer'),
    accessToken = Cookies.get('AccToken'),
    idUrl = Cookies.get('idURL'),
    connection;

function onload() {
    // Set the access token for the client's session, display the user info, and execute the query
    if (accessToken && apiVersion && instanceUrl) {
        setupConnection();
        executeQuery();
    } else {
        $('#result').html(
            'Some issue occurred during authentication. Please contact admin or try again by <a href="index.html">navigating here</a>.'
        );
    }

    // Execute the query and display results if the user presses the 'Enter' button on their keyboard while the query box has focus.
    $('#queryToExecute').keypress(function (e) {
        let key = e.which;

        // 13 is the key code for the 'Enter' key
        if (key == 13) {
            e.preventDefault();
            executeQuery();
        }
    });
}

function setupConnection() {
    connection = new jsforce.Connection({
        instanceUrl: instanceUrl,
        accessToken: accessToken,
        version: apiVersion,
    });
}

// Execute the query that's entered in the text box
function executeQuery() {
    let queryToExecute = $('#queryToExecute').val();

    connection.query(queryToExecute, (err, result) => {
        if (err) {
            $('#result').text('Error: ' + JSON.stringify(err));
        }
        let replacer = null,
            whitespace = 4;
        $('#result').text(JSON.stringify(result.records, replacer, whitespace));
        addAPICount();
    });
}

// Count the number of API calls since this page was loaded (just a gimmick)
function addAPICount() {
    apiCount++;
    $('#apiCount').text(apiCount);
}
