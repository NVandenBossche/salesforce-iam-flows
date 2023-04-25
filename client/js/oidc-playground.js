// Total steps is start + number of calls + finish
var totalSteps = 2 + authFlow.configuration.calls.length;
var currentStep = 1;
var endpoint = 'execute-step';

(async function initiate() {
    // Retrieve current state from the server
    const response = await fetch('/state');
    const state = await response.json();

    // Parse the state object
    currentStep = state.step;
    $('#baseurl').val(state.baseURL);
    $('#clientid').val(state.clientId);
    $('#clientsecret').val(state.clientSecret);
    $('#callbackurl').val(state.callbackURL);
    $('#code').val(state.authCode);
    $('#accesstoken').val(state.accessToken);
    $('#refreshtoken').val(state.refreshToken);
    $('#idtoken').val(state.idToken);
    $('#request > textarea').val(state.request);
    $('#response > textarea').val(state.response);

    // Activate the current step
    activateStep(currentStep);
})();

async function prev() {
    console.log('Previous Step...');

    const response = await fetch('/' + endpoint + '?direction=previous');
    const jsonResponse = await response.json();
    console.log(jsonResponse);

    // Deactivate current step
    deactivateStep(currentStep);

    // Increase step by 1
    currentStep--;

    // Activate previous step
    activateStep(currentStep);
}

async function next() {
    // Execute call corresponding to current step
    // Look to the first call in the authFlow
    let callToExecute = authFlow.configuration.calls[currentStep - 1];
    $('#request > textarea').html(JSON.stringify(callToExecute));

    const response = await fetch('/' + endpoint + '?direction=next');
    const jsonResponse = await response.json();

    if (jsonResponse.redirect) {
        window.location = jsonResponse.request;
    } else {
        // Deactivate current step
        deactivateStep(currentStep);

        // Increase step by 1
        currentStep++;

        // Activate previous step
        activateStep(currentStep);

        $('#request > textarea').val(JSON.stringify(jsonResponse.request, null, 2));
        $('#response > textarea').val(JSON.stringify(jsonResponse.response, null, 2));
        if (jsonResponse.response) {
            if (jsonResponse.response.access_token) {
                $('#accesstoken').val(jsonResponse.response.access_token);
            }
            if (jsonResponse.response.refresh_token) {
                $('#refreshtoken').val(jsonResponse.response.refresh_token);
            }
            if (jsonResponse.response.id_token) {
                $('#idtoken').val(jsonResponse.response.id_token);
            }
        }
        //}
    }
}

function activateStep(stepNumber) {
    // Set the step to active
    let activeStep = $('[data-target="#step' + stepNumber + '"]');
    let activeContent = $('#step' + stepNumber);
    activeStep.addClass('active');
    activeContent.addClass('active');

    // Hide Previous button if we're on the first step
    if (stepNumber === 1) {
        let previousButton = $('#previous-button');
        previousButton.hide();
    }

    // Hide Next button if we're on the last step
    if (stepNumber === totalSteps) {
        let nextButton = $('#next-button');
        nextButton.hide();
    }
}

function deactivateStep(stepNumber) {
    // Set the current step as inactive
    let inactiveStep = $('[data-target="#step' + stepNumber + '"]');
    let inactiveContent = $('#step' + stepNumber);
    inactiveStep.removeClass('active');
    inactiveContent.removeClass('active');
    $('#request > textarea').val('');
    $('#response > textarea').val('');

    // Show Previous button if we are on the first step
    if (stepNumber === 1) {
        let previousButton = $('#previous-button');
        previousButton.show();
    }

    // Show Next button if we were on the last step
    if (stepNumber === totalSteps) {
        let nextButton = $('#next-button');
        nextButton.show();
    }
}
