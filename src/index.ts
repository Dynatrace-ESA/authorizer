import express from "express";
import axios, { AxiosStatic } from 'axios';
import { dynatraceTokenRegex } from "@dt-esa/platform-constants";
import https from "https";

import passport from 'passport';
import { OIDCStrategy } from "passport-azure-ad";
import * as SamlStrategy from "passport-saml";
import { ScopeMap } from "./dynatrace-scopes";


export interface PermissionMap {
	[key: string]: Array<string>;
}

export type AuthenticationOptions = {
	// All modes
	mode: 'azure' | 'saml' | 'client' | 'dynatrace',
	authorizations?: PermissionMap,

	// Client mode
	clientConnectionPort?: number,

	// Dynatrace mode
	dynatraceEndpoint?: string,
	customAxios?: AxiosStatic,
	scopeMappings?: ScopeMap,

	// Saml mode
	saml?: any & {},
	// Azure mode
	azure?: any & {}
};

function getTokenPermissions(dtUrl: string, token: string, customAxios: AxiosStatic = axios): Promise<any> {
	return customAxios.post(dtUrl + `api/v1/tokens/lookup`, { token },
        {
            httpsAgent: new https.Agent({
                rejectUnauthorized: false
            }),
            headers: {
                Authorization: "Api-Token " + token
            }
        }
    );
}

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
export const authentication = (options: AuthenticationOptions) => {

    const { mode, clientConnectionPort }: AuthenticationOptions = options;
	const router = express.Router();

	let usercache: PermissionMap = {};

	let passportMethod: string;

	switch (mode) {
		case 'azure': {
			router.use(passport.initialize());
			router.use(passport.session());

			passport.serializeUser((user, done) => {
				done(null, user.oid);
			});

			passport.deserializeUser((oid, done) => {
				done(null, usercache[oid]);
			});

			passport.use(new OIDCStrategy(options.azure, 
				(iss, sub, profile, accessToken, refreshToken, done) => {
					
					if (!profile.oid) {
						return done(new Error('No oid found'), null);
					}
					// asynchronous verification, for effect...
					process.nextTick(() => {
						let user = usercache[profile.oid];

						if(!user) usercache[profile.oid] = profile;

						return done(null, user || profile);
					});
				})
			);


			// Always try to add the authorized scopes for further processing in the chain.
			router.use((req: any, res, next) => {
				if (!req._authorizedScopes) {
					// TODO: TBD
					const email = req.user?._json?.preferred_username;
					req._username = email;
					req._authorizedScopes = options.authorizations ? options.authorizations[email] : [];
				}
				next();
			});

			passportMethod = "azuread-openidconnect";

			break;
		}
		case 'saml': {
			router.use(passport.initialize());
			router.use(passport.session());

			passport.serializeUser((user, done) => {
				done(null, user.nameID);
			});

			passport.deserializeUser((nameID, done) => {
				let user = usercache[nameID];
				done(null, user);
			});

			const strategy = new SamlStrategy.Strategy(options.saml,
			 (profile: any, done: Function) => {
				// for signon
				process.nextTick(function () {
					let user = usercache[profile.nameID];

					if(!user) usercache[profile.nameID] = profile;

					return done(null, user || profile);
				});
			});

			passport.use(strategy);

			passportMethod = "saml";

			// Always try to add the authorized scopes for further processing in the chain.
			router.use((req: any, res, next) => {
				if (!req._authorizedScopes) {
					// TODO: TBD
					const email = req.user?.nameID;
					req._username = email;
					req._authorizedScopes = options.authorizations ? options.authorizations[email] : [];
				}
				next();
			});
			
			// ???
			router.get('/login/sso',
			passport.authenticate('saml', {
				successRedirect: '/',
				failureRedirect: '/login',
			}));

			break;
		}
		case 'client': { 
			router.use((req: any, res, next) => {

				// Pass if we don't have a session
				if(!req.cookies["connect.sid"])
					return next();
				
			
				axios
					.get(`https://127.0.0.1:${clientConnectionPort}/authorization`, {
						httpsAgent: new https.Agent({
							rejectUnauthorized: false
						}),
						headers: {
							Cookie: `connect.sid=` + req.cookies['connect.sid']
						},
					})
					.then(response => {
						const data: any = response.data;
						
						// If we have authorizations specified in client mode, then join them with the 
						// authorizations specified from the server.
						const locallyAppliedPermissions = options.authorizations 
														? options.authorizations[data.name] 
														: [] || []; // Always default as an empty array.

						req._username = data.name;
						req._authorizedScopes = data.permissions.concat(locallyAppliedPermissions);
						return next();
					});
			});
			break;
		}
		case 'dynatrace': { 
			router.use((req: any, res, next) => {

				if (!req.header('Authorization')) return next();

				const auth:  string = req.header('Authorization').replace('Basic ', '');    
				const token: string = Buffer.from(auth, 'base64').toString();

				// Quickly check that the token is in Dynatrace format.
				if (dynatraceTokenRegex.test(token)) {

					// If we have a token AND it's been cached for longer than 30 minutes, purge it.
					// This keeps us from caching tokens indefinitely.
					if (usercache[token] && 
						// @ts-expect-error
							((new Date().getTime() - usercache[token]._storeTime) > 30 * 60 * 1000)) {

						delete usercache[token];
					}

					const tokenId = token.length > 40 ? token.split('.').slice(0, 2).join('.') : (token.slice(0, 4) + "*****************");

					if(usercache[token]) {
						req._username = tokenId;
						req._authorizedScopes = usercache[token];
						req._scopeMapping = options.scopeMappings;
						return next();
					}
					else {
						let dtUrl = options.dynatraceEndpoint;
						if (!dtUrl.endsWith('/')) dtUrl += '/';
						if (!dtUrl.startsWith('https://')) dtUrl = "https://" + dtUrl;

						console.info(`Checking token permissions via ${dtUrl}api/v1/tokens/lookup/${tokenId}`);

						return getTokenPermissions(dtUrl, token, options.customAxios).then(({ data }) => {
							console.info(`Recieved token permissions via ${dtUrl}api/v1/tokens/lookup/${tokenId}`);

							if (!data) {
								console.warn(`Failed to validate token ${dtUrl}api/v1/tokens/lookup/${tokenId}`);
								return next({ 
									status: 401, 
									message: "Could not validate token" 
								});
							}
	
							if (data.revoked == true) {
								console.warn(`Token is revoked ${dtUrl}api/v1/tokens/lookup/${tokenId}`);
								return next({ 
									status: 401, 
									message: "Token is revoked" 
								});
							}
	
							if (data.expires && (data.expires > new Date().getTime())) {
								console.warn(`Token is expired ${dtUrl}api/v1/tokens/lookup/${tokenId}`);
								return next({ 
									status: 401, 
									message: "Token is expired" 
								});
							}

							// Timestamp when this was added into the cache
							data.scopes._storeTime = new Date().getTime();
							
							req._username = tokenId;
							req._authorizedScopes = usercache[token] = data.scopes;
							req._scopeMapping = options.scopeMappings;
	
							next();
						}).catch(next);
					}
				}
				else {
					// Invalid or missing API token
					return next({
						status: 401,
						message: "Invalid Credentials"
					});
				}
			});
			break;
		}
	}

	if (mode != 'dynatrace' && mode != 'client') {
		router.get('/login', (req, res, next) =>
				passport.authenticate(passportMethod, {
					response: res, // required
					failureRedirect: '/',
				})(req, res, next),
			(req, res) => {
				console.info('Login was called in the Sample');
				res.redirect('/');
			}
		);

		router.use('/code', (req, res, next) => {
				passport.authenticate(passportMethod, {
					response: res, // required
					failureRedirect: '/',
				})(req, res, next);
			},
			(req, res) => {
				res.redirect('/');
			}
		);

		router.get('/logout', (req: any, res) => {
			req.session.destroy((err) => {
				req.logOut();
				res.redirect('/');
			});
		});
	}

	// Single endpoint to get authorized user permissions.
	router.get('/authorization', (req: any, res, next) => {

		// Skip authorization requests in Client mode.
		if (mode == "client") {
			return next();
		}

		// Calculate and return all of the authorized scopes.
		if (req._authorizedScopes) {
			const scopeMapping: PermissionMap = req._scopeMapping || {};
			const authorizedScopes = req._authorizedScopes;

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
export const authorize = (permissions: Array<string> = []) => {
    return (req: any, res, next) => {

		// Our request isn't authorized: Reject.
		if (!req._authorizedScopes) {
			return next({
				status: 401,
				message: 'Authorization could not be established.',
			});
		}

		const scopeMapping: PermissionMap = req._scopeMapping || {};
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
}