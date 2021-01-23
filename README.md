# Salesforce SAML and OAuth 2.0 authorization flows using Node.js

[![Youtube demo Video](https://img.youtube.com/vi/Iez9xdKbeuk/0.jpg)](https://www.youtube.com/watch?v=Iez9xdKbeuk)

# Steps to run

### Prerequisites

Create a [Heroku](https://heroku.com) account if you don't already have one.

Install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli#download-and-install).

### Step 1

Click on the below button to deploy this application on Heroku.

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

### Step 2

#### Step 2.1 (Optional) Generate your own private key and public certificate

This step can be skipped if you're ok using the private key and public certificate that is stored in this Github repository.
Be aware that this isn't safe.

-   Install openssl by following the [instructions](https://github.com/openssl/openssl#build-and-install) on its Github repository.
-   Clone this repository to your local machine.
-   Run the following command in the root of the cloned repository: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out server.crt -days 365 -noenc`
-   Set your [Heroku remote](https://devcenter.heroku.com/articles/git#for-an-existing-heroku-app).
-   Stage these changes, commit them and then [push](https://devcenter.heroku.com/articles/git#deploying-code) to the heroku master.

#### Step 2.2 Create Connected App

Create a Connected App in your Salesforce org. The Connected App should have the following settings:

-   Basic Information: Fill out Name and your Email, leave everything else blank.
-   API
    -   Enable OAuth Settings: check this.
    -   Callback URL: set to 'https://localhost:8081/oauthcallback' (if running locally) or 'https://your-heroku-app.herokuapp.com:8081/oauthcallback' (if running on Heroku)
    -   Use digital signature: check this and upload the 'server.crt' file (either from this Github repository or self-generated certificate).
    -   Selected OAuth scopes: you can play with this but for all flows to fully function you'll need 'full', 'openid' and 'refresh_token'.
    -   Require secret for web server flow: uncheck this (unless you want to specifically test this setting).
    -   Leave all other settings as default.
-   Web App Settings: leave default.
-   Custom Connected App Handler: leave default.
-   Mobile App Settings: leave default.
-   Canvas App Settings: leave default.

#### Step 2.3 - Set Connected App Policies

From the newly created Connected App, click 'Manage', then 'Edit Policies'. Under 'OAuth Policies', selected 'Admin approved users are pre-authorized' for 'Permitted Users'.

After saving, add the correct profile of your user or add a permission set that is assigned to your user.

### Step 3

Update the Config Vars of your Heroku app (Settings > Config Vars) for the following key-value pairs.

-   PORT=8080
-   CLIENT_ID=<your_client_id>
-   CLIENT_SECRET=<your_client_secret>
-   BASE_URL=<your_mydomain_url>
-   CALLBACK_URL=https://<your_herokuapp>:8081/oauthcallback
-   USERNAME=<your_Salesforce_username>
-   PERSIST=false

### Step 5

Wait until the Heroku application is deployed and navigate to the Heroku app.

# Local testing

There's also a possibility to test a Heroku app locally. If you're taking this approach, keep the following in mind:

-   You'll need a local installation of Node.js and install the correct package dependencies.
-   Make sure the date & time are set automatically on your local machine to avoid time skew in your messages.
-   Create a .env file in the root of your project directory that contains the environment variables.
