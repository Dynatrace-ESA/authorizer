#### @dt-esa/authorizer

This package provides passport handling for authorization and scope correlation. 

Intended for use in Dynatrace ESA Solutions.

```ts
import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import expressSession from 'express-session';
import { authentication } from '@dt-esa/authorizer';

const app: Express = express();

app.use(cookieParser());
app.use(expressSession({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));
app.use(express.urlencoded({ extended : true }));

app.use(authentication({
    mode: 'dynatrace',
    dynatraceEndpoint: "https://kkr04563.sprint.dynatracelabs.com/"
}));
```

Available Options for Authorizations

```ts
{
 * 	   mode: 
 * 			 "client"    | // Use a seperate webserver running this middleware to authenticate & authorize transactions.
 * 			 "dynatrace" | // Use a Dynatrace instance to authenticate transactions and provide authorization.
 * 			 "azure"     | // Use Azure App Registration for Authentication. Authorization specified in `authorizations`.
 * 			 "saml",       // Use a generic SAML configuration for Authentication. Authorization specified in `authorizations`.
 * 	   authorizations?: Map<string, Array<string>>, // For `azure` and `saml` modes. An object containing Authorizations to apply.
 * 			// e.g.
 * 			// {
 * 			//     "grace.hopper@example.com": ["ReadConfig", "WriteConfig", "logs.read"],
 * 			//     "ryan.dahl@example.com":    ["WriteConfig", "logs.read"],
 * 			//     "brendan.eich@example.com": ["ReadConfig", "logs.read"],
 * 			// ...
 * 			// }
 *     saml?: Object,      // SAML configuration object provided to "passport-saml"
 *     azure?: Object,     // Azure configuration object provided to "passport-azure-ad"
 *     clientConnectionPort?: number, // When mode is `client`, the port that the seperate webserver authorizing transactions is running on.
 *     dynatraceEndpoint?:    string  // The URL that the Authorizer will check against for Dynatrace Authorization.
 * }
```

