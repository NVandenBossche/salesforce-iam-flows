# Salesforce SAML and OAuth 2.0 authorization flows using Node.js

This application is an example implementation in Node.js of the different SAML and OAuth flows that are supported by Salesforce.
Please leverage this repository as learning material, rather than something to be used in production.

## Introduction

When I was preparing for the Salesforce Certified Technical Architect (CTA) certification, Identity & Access Management (IAM)
was one of the topics I struggled with. Mainly because I hadn't come into contact with it frequently during any projects I'd worked on.

I knew how to set up Single Sign-On (SSO), but that didn't compare to understanding the more delicate
complexities of the different OAuth flows. So I started diving into this topic in detail.

There were two resources that were invaluable to me:

1. A very lengthy conversation about different IAM topics with _Lawrence Newcombe_. Lawrence has actually taken the outcome of these discussions and created very clear diagrams from them on his [personal blog](https://cloudsundial.com/salesforce-identity).
2. A [blog post](https://www.jitendrazaa.com/blog/salesforce/using-jwt-flow-to-authenticate-nodejs-application-with-salesforce/) about a Node.js application implementing the JWT OAuth flow by _Jitendra Zaa_.

At first, I expanded upon Jitendra's work by adding the flows I struggled with most. After passing the CTA board,
I wanted to build it out further to include the majority of OAuth flows so that others could also learn from it.

It took a while but I've finally built it.

## Video walkthrough

!! This video is outdated - planning to update soon

You can find a video walkthrough of how to install and set up the application on your personal Heroku environment.
Click the below image to launch the video on Youtube.

[![Video walkthrough](https://img.youtube.com/vi/iWU9hJ26WuE/0.jpg)](https://www.youtube.com/watch?v=iWU9hJ26WuE)

## Steps to run

Step-by-step instructions on how to get the application up and running.

You can run this application locally via Node.js or on Heroku.

### Prerequisites

Create a [Heroku](https://heroku.com) account if you don't already have one.

If you want to run the application locally, install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli#download-and-install).

### Step 1

#### Step 1.1 Generate your own private key and public certificate

For some of the OAuth flows, we'll need a public certificate (or public key) and upload it to the Connected App.

We'll either need to generate our own public & private key, or you can use the ones in this repository. Both keys are stored in the root folder:

-   key.pem is the private key
-   server.crt is the public key (certificate)
    Be aware that this isn't safe and you should only do this for Salesforce environments that you don't mind getting compromised.

To generate your own private key and public certificate, follow these steps

-   Install openssl by following the [instructions](https://github.com/openssl/openssl#build-and-install) on its Github repository.
-   Clone this repository to your local machine.
-   Run the following command in the root of the cloned repository:
    -   For OpenSSL 3.0 and above: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out server.crt -days 365 -noenc`
    -   For earlier versions of OpenSSL: `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out server.crt -days 365 -nodes`

#### Step 1.2 Create Connected App

Create a Connected App in your Salesforce org. The Connected App should have the following settings:

-   Basic Information: Fill out Name and your Email, leave everything else blank.
-   API
    -   Enable OAuth Settings: check this.
    -   Enable for Device Flow: check this too.
    -   Callback URL: set to 'https://localhost:8081/services/oauth2/success' (if running locally) or 'https://your-heroku-app.herokuapp.com/services/oauth2/success' (if running on Heroku)
    -   Use digital signature: check this and upload the 'server.crt' file (either from this Github repository or self-generated certificate).
    -   Selected OAuth scopes: you can play with this but for all flows to fully function you'll need 'full', 'openid' and 'refresh_token'.
    -   Require secret for web server flow: uncheck this (unless you want to specifically test this setting).
    -   Leave all other settings as default.
-   Web App Settings: leave default.
-   Custom Connected App Handler: leave default.
-   Mobile App Settings: leave default.
-   Canvas App Settings: leave default.

#### Step 1.3 - Set Connected App Policies

From the newly created Connected App, click 'Manage', then 'Edit Policies'. Under 'OAuth Policies', selected 'Admin approved users are pre-authorized' for 'Permitted Users'.

After saving, add the correct profile of your user or add a permission set that is assigned to your user.

### Step 2

#### Option 1 - Deploying to Heroku

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

-   Click on the above button to deploy this application on Heroku.
-   If you've created your own private & public keys:
    -   In your local terminal, set your [Heroku remote](https://devcenter.heroku.com/articles/git#for-an-existing-heroku-app).
    -   Stage the changes to the key files, commit them and then [push](https://devcenter.heroku.com/articles/git#deploying-code) to the heroku master.
-   Update the Config Vars of your Heroku app (Settings > Config Vars) for the following key-value pairs.
    -   PORT = 8080
    -   CLIENT_ID = client ID / consumer key of your connected app
    -   CLIENT_SECRET = client secret / consumer secret of your connected app
    -   BASE_URL = myDomain URL of your Salesforce org
    -   CALLBACK_URL = callback URL added to your connected app
    -   USERNAME = Salesforce username
    -   API_VERSION = Salesforce API version (e.g. 57.0)
    -   PERSIST = false

#### Option 2 - Running locally

-   Create a file ".env" in the root directory with the following contents
    ```
    PORT=8080
    CALLBACK_URL=https://localhost:8081/services/oauth2/success
    PERSIST=true
    CLIENT_ID=3MVG9Rd3qC6oMalWJCSJXAUD00hp7CXsrAV._dFrbch4jYXUOu_kAuP0uuRsrzMSSwYqldy5qdylySUwZvkn3
    CLIENT_SECRET=B2ABE781A2EA7927084257478BB783074DD7E79A220758439D5F575C4FC6B7BF
    BASE_URL=https://nicolasvandenbossche-dev-ed.my.salesforce.com
    USERNAME=n.vanden.bossche@accenture.com
    API_VERSION=57.0
    ```
-   Open a terminal in the root directory and run the following commands:
    ```
    npm install
    node -r dotenv/config Server.js
    ```

### Step 3

Navigate to your app, either on Heroku or locally (via https://localhost:8081). Go to the flow you're interested in, read the description and
click the Launch button to execute.
