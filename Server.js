// Load Express and other dependencies
var express = require('express'),
    http = require('http'), 
    request = require('request'),
    bodyParser = require('body-parser'),
	morgan = require('morgan'),
    app = express(), 
	path = require("path"),
	https = require('https'), 
	fs = require('fs'),  
	base64url = require('base64-url'), 
	nJwt = require('njwt'),
	CryptoJS = require('crypto-js'),
	apiVersion = 'v45.0',
	domainName='localhost:8081',
	clientId = process.env.CLIENT_ID, 
	clientSecret=process.env.CLIENT_SECRET,
	callbackURL = process.env.CALLBACK_URL,
	baseURL = process.env.BASE_URL,
	codeVerifier = '',
	jwt_aud = 'https://nicolasvandenbossche-dev-ed.my.salesforce.com';

// Set default view engine to ejs. This will be used when calling res.render()
app.set('view engine', 'ejs');

// Let Express know where the client files are located
app.use(express.static(__dirname + '/client')); 

// Setting up of app
app.use(morgan('dev'));
app.use(bodyParser.json());  
app.use(bodyParser.urlencoded({extended : true}));

// Set the port to use based on the environment variables
app.set('port', process.env.PORT);

/**
 * Extract Access token from POST response and redirect to page Main
 */
function extractAccessToken(err, remoteResponse, remoteBody,res){
	if (err) { 
		return res.status(500).end('Error'); 
	}
	console.log(remoteBody) ;
	var sfdcResponse = JSON.parse(remoteBody); 
	
	//success
	if(sfdcResponse.access_token){				 
		res.writeHead(302, {
		  'Location': 'Main' ,
		  'Set-Cookie': ['AccToken='+sfdcResponse.access_token,'APIVer='+apiVersion,'InstURL='+sfdcResponse.instance_url,'idURL='+sfdcResponse.id]
		});
	}else{
		res.write('Some error occurred. Make sure connected app is approved previously if its JWT flow, Username and Password is correct if its Password flow. ');
		res.write(' Salesforce Response : ');
		res.write( remoteBody ); 
	} 
	res.end();
}

/**
 * Function that generates a cryptographically random code verifier
 * @returns Cryptographically random code verifier
 */
function generateCodeVerifier() {
	return code_verifier = base64URL(CryptoJS.lib.WordArray.random(32));
}

/**
 * Function that hashes the code verifier and encodes it into base64URL
 * @param {String} code_verifier
 * @returns Code challenge based on provided code_verifier
 */
function generateCodeChallenge(code_verifier) {
	return code_challenge = base64URL(CryptoJS.SHA256(code_verifier));
}

/**
 * Base64URL encode the given string
 * @param {String} string 
 */
function base64URL(string) {
	return string.toString(CryptoJS.enc.Base64).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

app.all('/proxy',  function(req, res) {     
    var url = req.header('SalesforceProxy-Endpoint');  
    request({ url: url, method: req.method, json: req.body, 
                    headers: {'Authorization': req.header('X-Authorization'), 'Content-Type' : 'application/json'}, body:req.body }).pipe(res); 
});

app.get('/jwt', function (req,res){  
	var isSandbox = req.query.isSandbox;
	var sfdcURL = 'https://nicolasvandenbossche-dev-ed.my.salesforce.com/services/oauth2/token' ;
	if(isSandbox == 'true'){
		sfdcURL = 'https://test.salesforce.com/services/oauth2/token' ;
	}
	var sfdcUserName = req.query.jwtUserName;
	var token = getJWTSignedToken_nJWTLib(sfdcUserName); 
	  
	var paramBody = 'grant_type='+base64url.escape('urn:ietf:params:oauth:grant-type:jwt-bearer')+'&assertion='+token ;	
	var req_sfdcOpts = { 	url : sfdcURL,  
							method:'POST', 
							headers: { 'Content-Type' : 'application/x-www-form-urlencoded'} ,
							body:paramBody 
						};
				
	request(req_sfdcOpts, 
		function(err, remoteResponse, remoteBody) {
			extractAccessToken(err, remoteResponse, remoteBody, res); 
		} 
	); 
} );

/**
 * Step 1 Web Server Flow - Get Code
 */
app.get('/webServer', function (req,res){	
	// Set parameter values based on environment variables
	var sfdcURL = baseURL + '/services/oauth2/authorize';
	var state = 'webServerProd';
	var responseType = 'code';
	var scope = 'full%20refresh_token';
	
	codeVerifier = generateCodeVerifier();
	var codeChallenge = generateCodeChallenge(codeVerifier);

	if(req.query.isSandbox == 'true'){
		sfdcURL = 'https://test.salesforce.com/services/oauth2/authorize' ;
		state = 'webServerSandbox';
	}

	var authorizationUrl = sfdcURL +
								'?client_id=' + clientId +
								'&redirect_uri=' + callbackURL +
								'&response_type=' + responseType +
								'&state=' + state + 
								'&scope=' + scope +
								'&code_challenge=' + codeChallenge;
	
	 request({url: authorizationUrl, method: 'GET'}).pipe(res);
} );



/**
 * Step 2 Web Server Flow - Get token from Code
 */
app.get('/webServerStep2', function (req,res) {  
	var sfdcURL = baseURL + '/services/oauth2/token';
	var grantType = 'authorization_code';
	var code = req.query.code;
	var state = req.query.state;

	if(state == 'webServerSandbox'){
		sfdcURL = 'https://test.salesforce.com/services/oauth2/token' ;
	}

	var tokenUrl = sfdcURL +
						'?client_id=' + clientId +
						'&client_secret=' + clientSecret +
						'&redirect_uri=' + callbackURL +
						'&grant_type=' + grantType +
						'&code=' + code +
						'&state=' + state + 
						'&code_verifier=' + codeVerifier;
		
	 request({url: tokenUrl, method: 'POST'}, function(err, remoteResponse, remoteBody) {
				extractAccessToken(err, remoteResponse, remoteBody, res); 
		} 
	);
});


/**
*	 User Agent oAuth Flow
*/
app.get('/uAgent', function (req,res){  
	var isSandbox = req.query.isSandbox;
	var sfdcURL = baseURL + '/services/oauth2/authorize' ;
	if(isSandbox == 'true'){
		sfdcURL = 'https://test.salesforce.com/services/oauth2/authorize' ;
	}
	
	 request({ 	url : sfdcURL+'?client_id='+process.env.CLIENT_ID+'&redirect_uri='+process.env.CALLBACK_URL+'&response_type=token',  
				method:'GET' 
			}).pipe(res); 
	 
} );

/**
*	 Username Password oAuth Flow
*/
app.post('/uPwd', function (req,res){  

	var instance = req.body.instance;
	var uname = req.body.sfdcUsername;
	var pwd = req.body.sfdcPassword; 

	var state = req.query.state;
	var sfdcURL = 'https://nicolasvandenbossche-dev-ed.my.salesforce.com/services/oauth2/token' ;
	if(instance == 'sand'){
		sfdcURL = 'https://test.salesforce.com/services/oauth2/token' ;
	}
	
	var computedURL = sfdcURL+
	'?client_id='+ clientId+
	 '&grant_type=password'+
	 '&client_secret='+clientSecret+
	 '&username='+uname+
	 '&password='+pwd ;
 

	 request({ 	url : computedURL,  
				method:'POST' 
			},
			function(err, remoteResponse, remoteBody) {
				extractAccessToken(err, remoteResponse, remoteBody, res); 
			} 
		);  
} );

/**
 * Device Authentication Flow
 */
app.get('/device', function (req,res){  

	var isSandbox = req.query.isSandbox;
	var sfdcURL = 'https://nicolasvandenbossche-dev-ed.my.salesforce.com/services/oauth2/token' ;
	if(isSandbox == 'true'){
		sfdcURL = 'https://test.salesforce.com/services/oauth2/token' ;
	}
	
	var computedURL = sfdcURL+
	'?client_id='+ clientId+
	 '&response_type=device_code' ;
 

	 request({ 	url : computedURL,  
				method:'POST' 
			},
			function(err, remoteResponse, remoteBody) {
				if (err) { 
					res.write(err);
					res.end();
					//return res.status(500).end('Error'); 
					return  ;
				}
				console.log(remoteBody) ;
				var sfdcResponse = JSON.parse(remoteBody); 

				if(sfdcResponse.verification_uri){
					res.render('deviceOAuth',{
						verification_uri : sfdcResponse.verification_uri,
						user_code : sfdcResponse.user_code,
						device_code : sfdcResponse.device_code,
						isSandbox : isSandbox
					}); 
				}  
			} 
		);  
} ); 

/**
 *  Keep polling till device is verified using code
 */

app.get('/devicePol', function (req,res){  

	var isSandbox = req.query.isSandbox;
	var verification_uri = req.query.verification_uri;
	var user_code = req.query.user_code;
	var device_code = req.query.device_code;

	var sfdcURL = 'https://nicolasvandenbossche-dev-ed.my.salesforce.com/services/oauth2/token' ;
	if(isSandbox == 'true'){
		sfdcURL = 'https://test.salesforce.com/services/oauth2/token' ;
	}
	
	var computedURL = sfdcURL+
	'?client_id='+ clientId+
	 '&grant_type=device'+
	 '&code='+device_code ;

	 request({ 	url : computedURL,  
			method:'POST' 
		},
		function(err, remoteResponse, remoteBody) {
			if (err) { 
				return res.status(500).end('Error'); 
			}
			console.log(remoteBody) ;
			var sfdcResponse = JSON.parse(remoteBody); 

			if(sfdcResponse.access_token){ 
				res.writeHead(302, {
					'Location': 'Main' ,
					'Set-Cookie': ['AccToken='+sfdcResponse.access_token,'APIVer='+apiVersion,'InstURL='+sfdcResponse.instance_url,'idURL='+sfdcResponse.id]
				  });
				  res.end();
			} else{
				res.render('deviceOAuth',{
					verification_uri :  verification_uri,
					user_code :  user_code,
					device_code :  device_code,
					isSandbox : isSandbox
				});
			}
		} 
	);  
} ); 

 

function getJWTSignedToken_nJWTLib(sfdcUserName){ 
	var claims = {
	  iss: clientId,   
	  sub: sfdcUserName,     
	  aud: jwt_aud,
	  exp : (Math.floor(Date.now() / 1000) + (60*3))
	}

	return encryptUsingPrivateKey_nJWTLib(claims);
}

function encryptUsingPrivateKey_nJWTLib (claims) {
	var absolutePath = path.resolve("key.pem"); 	
    var cert = fs.readFileSync(absolutePath );	
	var jwt_token = nJwt.create(claims,cert,'RS256');	
	console.log(jwt_token);	
	var jwt_token_b64 = jwt_token.compact();
	console.log(jwt_token_b64);
 
	return jwt_token_b64;     
};

app.get('/' ,  function(req,res) {
    res.render('index',{callbackURL:process.env.CALLBACK_URL, baseURL:baseURL});
} ); 

app.get('/index*' ,  function(req,res) {
    res.render('index',{callbackURL:process.env.CALLBACK_URL, baseURL:baseURL});
} );  
 
app.get('/oauthcallback' ,  function(req,res) {
    res.render('oauthcallback');
} ); 

app.get('/Main*' ,   function(req,res) {
    res.sendfile('views/Main.html');
} );
  
app.listen(app.get('port'), function () {
    console.log('Express server listening on port ' + app.get('port'));
});

var options = {
  key: fs.readFileSync('./key.pem', 'utf8'),
  cert: fs.readFileSync('./server.crt', 'utf8')
};

https.createServer(options, app).listen(8081);
console.log("Server listening for HTTPS connections on port ", 8081);
