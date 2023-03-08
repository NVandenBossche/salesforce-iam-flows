var totalSteps = 2 + authFlow.configuration.calls.length * 2;
var currentStep = 1;

function prev() {
    console.log('Previous Step...');
    // Deactivate current step
    deactivateStep(currentStep);

    // Increase step by 1
    currentStep--;

    // Activate previous step
    activateStep(currentStep);
}

function next() {
    // Deactivate current step
    deactivateStep(currentStep);

    // Increase step by 1
    currentStep++;

    // Activate previous step
    activateStep(currentStep);
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
