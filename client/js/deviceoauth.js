// Navigate to the same page every [interval] seconds
window.setInterval(function () {
    window.location =
        'devicePol?device_code=' +
        device_code +
        '&user_code=' +
        user_code +
        '&isSandbox=' +
        isSandbox +
        '&interval=' +
        interval +
        '&verification_uri=' +
        verification_uri;
}, interval * 1000);
