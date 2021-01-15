# Salesforce SAML and OAuth 2.0 authorization flows using Node.js

[![Youtube demo Video](https://img.youtube.com/vi/Iez9xdKbeuk/0.jpg)](https://www.youtube.com/watch?v=Iez9xdKbeuk)

# Steps to run

### Prerequisites

Create a [Heroku](https://heroku.com) account if you don't already have one.

### Step 1

Click on the below button to deploy this application on Heroku.
[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

### Step 2

Create a private key and public certificate using openssl. Store the key as 'key.pem' and the certificate as 'server.crt' in the root of the Heroku Git repository corresponding to the app. [Refer this post to learn how to create ssl certificate using openssl](http://www.jitendrazaa.com/blog/salesforce/use-lightning-components-on-external-websites-lightning-out/)

### Step 3

Create a Connected App in your Salesforce org, with the following settings:

-   Basic Information: Fill out Name and your Email, leave everything else blank.
-   API
    -   Enable OAuth Settings: check this.
    -   Callback URL: set to 'https://localhost:8081/oauthcallback' (if running locally) or 'https://your-heroku-app.herokuapp.com:8081/oauthcallback' (if running on Heroku)
    -   Use digital signature: check this and upload the 'server.crt' file.
    -   Selected OAuth scopes: you can play with this but for all flows to fully function you'll need 'full', 'openid' and 'refresh_token'.
    -   Require secret for web server flow: uncheck this (unless you want to specifically test this setting).
    -   Introspect all tokens: uncheck this.
    -   Configure ID Token: uncheck this.
    -   Enable Asset Tokens: uncheck this. Currently not implemented.
    -   Enable Single Logout: uncheck this.
-   Web App Settings: leave blank.
-   Custom Connected App Handler: leave blank.
-   Mobile App Settings: leave blank.
-   Canvas App Settings: leave blank.

### Step 4

Update the environment variables for at least the following key-value pairs.
PORT=8080
CLIENT_ID=<your_client_id>
CLIENT_SECRET=<your_client_secret>
BASE_URL=<your_mydomain_url>
CALLBACK_URL=https://<your_herokuapp>:8081/oauthcallback
USERNAME=<your_Salesforce_username>
PERSIST=true

### Step 5

Restart the Heroku application.

### Step 6

Navigate to the Heroku app.

### Step 7

If you're testing locally, make sure the date & time are set automatically on your local machine to avoid time skew in your messages.
