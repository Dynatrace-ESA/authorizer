import { SessionStoreClient, SharedSessionStore } from "@dt-esa/level-cluster";
import { Client } from "./flows/client";
import { Dynatrace } from "./flows/dynatrace";
import { OpenId } from "./flows/openid";
import { Saml } from "./flows/saml";
import passport from 'passport';
import express from 'express';

/**
 * Connect-style middleware that sets up SSO authorization via passport.
 *
 *
 * @param options
 * ```ts
 * type AuthorizatonHandlerOptions = {
 * 	   mode:
 * 			 "client"    | // Use a seperate webserver running this middleware to authenticate & authorize transactions.
 * 						   // If `authorizations` is specified in both the client and server, the resulting request will have the permissions from both.
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
 *     customAxios?:   	      AxiosStatic // An optional axios client.
 *	   scopeMappings?: Map<string, Array<string>>, // A mapping of scope ID from the Dynatrace API to your router. This is only used in "dynatrace" mode.
 *
 * }
 * ```
 *
 *
 * This will export an express router with several route handlers:
 *  - `login`         (redirect to login provider)
 *  - `code`          (recieve the SAML/OpenID/Oauth response)
 *  - `logout`        (log user out & redirect back to root)
 *  - `authorization` (endpoint to check authorization)
 *
 * All subsequent requests in the chain will be decorated with the following properties:
 *  - `_username`:         string
 *  - `_scopeMapping`:     Map<string, Array<string>>
 *  - `_authorizedScopes`: Array<string>
 */
export const authentication = (port, options) => {
    const router: any = express.Router();
    const cache = new SessionStoreClient(port, "@dynatrace-esa/authorizer");
    // Initialize Passport.
    router.use(passport.initialize());
    router.use(passport.session());
    // Allow us to use multiple flows at the same time.
    if (options.dynatrace)
        Dynatrace(router, cache, options.dynatrace);
    if (options.saml)
        Saml(router, cache, options.saml, passport);
    if (options.openid)
        OpenId(router, cache, options.openid);
    if (options.client)
        Client(router, options.client);
    // By this point, all of the authorization flows are registered.
    // If we have a session, we are already logged in and the request is decorated.
    // All paths that have a session log out this way.
    router.get('/logout', (req, res) => {
        // Destroy the session from the express session store.
        req.session.destroy((err) => {
            req.logOut();
            res.redirect('/');
        });
    });
    router.use((req, res, next) => {
        // Decorate all SSO login flows.
        // Dynatrace flow will add scopes automatically.
        req._authorizedScopes = req._authorizedScopes || [];
        req._authorizedScopes =
            req._authorizedScopes.concat(options.authorizations ? options.authorizations[req._username] || [] : []);
        next();
    });
    // Single endpoint to get authorized user permissions.
    router.get('/authorization', (req, res, next) => {
        // Calculate and return all of the authorized scopes.
        if (req._username) {
            const scopeMapping = req._scopeMapping || {};
            const authorizedScopes = req._authorizedScopes || [];
            // Calculate ALL grants the request has if there is a mapping specified.
            const mappedScopes = Object.keys(scopeMapping).flatMap(key => {
                return authorizedScopes[key] ? scopeMapping[key] : [];
            });
            const userScopes = authorizedScopes.concat(mappedScopes);
            return res.send({
                name: req._username,
                permissions: userScopes
            });
        }
        // Our request isn't authorized. Reject.
        next({
            status: 401,
            message: 'Authorization could not be established.',
        });
    });
    return router;
};

/**
 * Connect-style middleware that asserts all permissions are satisfied by the
 * authenticated user. If a permission is missing, it will reject the transaction.
 * @param permissions A list of required Permissions or Scopes an authorized part must have.
 *
 * - Invoking this method with an empty array or no permissions specified will simply ensure
 * that the user is authenticated.
 */
export const authorize = (permissions = []) => {
    return (req, res, next) => {
        // Our request isn't authorized: Reject.
        if (!req._authorizedScopes) {
            return next({
                status: 401,
                message: 'Authorization could not be established.',
            });
        }
        const scopeMapping = req._scopeMapping || {};
        const authorizedScopes = req._authorizedScopes;
        // Calculate ALL grants the request has if there is a mapping specified.
        const mappedScopes = Object.keys(scopeMapping).flatMap(key => {
            return authorizedScopes[key] ? scopeMapping[key] : [];
        });
        const userScopes = authorizedScopes.concat(mappedScopes);
        const missingScopes = permissions.filter(p => !userScopes.includes(p));
        // We have all of the scopes we need.
        if (missingScopes.length == 0) {
            return next();
        }
        // We aren't allowed to do this.
        else {
            return next({
                status: 403,
                message: 'User does not have authorization to access this resource.'
            });
        }
    };
};

/**
 * Method to initialize the shared user cache.
 * This is present as an example.
 *
 * Alternatively you can create a SharedSessionStore on the target port
 * with the instanceId "@dynatrace-esa/authorizer" manually.
 *
 * @param port port on which the shared memory store communicates.
 * @param options
 */
export const SharedUserCache = (port, options) => {
    // We will always use the authorizer cache id. This will prevent collisions with other 
    // packages that need to use a cache.
    options.instanceId = "@dynatrace-esa/authorizer";
    return new SharedSessionStore(port, options);
};
