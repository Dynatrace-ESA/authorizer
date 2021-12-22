import express from "express";
import axios from 'axios';
import { dynatraceTokenRegex } from "@dt-esa/platform-constants";
import https from "https";

import passport from 'passport';
import { OIDCStrategy } from "passport-azure-ad";
import * as SamlStrategy from "passport-saml";

export type AuthorizatonHandlerOptions = {
	mode: 'azure' | 'saml' | 'client' | 'dynatrace',
	endpoint?: string,
	authorizations?: Map<string, Array<string>>,
	saml?: any & {},
	azure?: any & {}
};

const authorizationDefaults: AuthorizatonHandlerOptions = {
	mode: 'dynatrace'
};

function getTokenPermissions(token: string): Promise<any> {
    const dtUrl: string = globalThis.config.dtUrl;
    console.info(`Checking token permissions via ${dtUrl}api/v1/tokens/lookup/${token.replace(/\..+$/, '')}`);
    
    return axios.post(dtUrl + `api/v1/tokens/lookup`, { token },
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

export const AuthorizationHandler = (options: AuthorizatonHandlerOptions) => {

    const { mode }: AuthorizatonHandlerOptions = { ...authorizationDefaults, ...options };
	const router = express.Router();

	let usercache = {};

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
					req._authorizedScopes = options.authorizations[email];
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
					req._authorizedScopes = options.authorizations[email];
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
					.get(`https://127.0.0.1:6800/authorization`, {
						httpsAgent: new https.Agent({
							rejectUnauthorized: false
						}),
						headers: {
							Cookie: `connect.sid=` + req.cookies['connect.sid']
						},
					})
					.then(response => {
						const data: any = response.data;
						req._username = data.name;
						req._authorizedScopes = data.permissions;
						return next();
					});
			});
			break;
		}
		case 'dynatrace': { 
			router.use((req: any, res, next) => {
				if(!req.header('Authorization')) return next();

				const auth:  string = req.header('Authorization').replace('Basic ', '');    
				const token: string = Buffer.from(auth, 'base64').toString();

				if(dynatraceTokenRegex.test(token)){

					// If we have a token AND it's been cached for longer than 30 minutes, purge it.
					// This keeps us from caching tokens indefinitely.
					if (usercache[token] && 
					 	((new Date().getTime() - usercache[token]._storeTime) > 30 * 60 * 1000)) {

						delete usercache[token];
					}

					if(usercache[token]){
						req._username = token.length > 40 ? token.split('.').slice(0,2).join('.') : (token.slice(0,4) + "*****************");
						req._authorizedScopes = usercache[token];
						return next();
					}
					else {
						return getTokenPermissions(token).then(({ data }) => {
							if (!data) {
								throw { 
									status: 401, 
									message: "Could not validate token" 
								};
							}
	
							if (data.revoked == true) {
								throw { 
									status: 401, 
									message: "Token is revoked" 
								};
							}
	
							if (data.expires && (data.expires > new Date().getTime())) {
								throw { 
									status: 401, 
									message: "Token is expired" 
								};
							}

							// Timestamp when this was added into the cache
							data.scopes._storeTime = new Date().getTime();
							
							req._username = token.length > 40 ? token.split('.').slice(0,2).join('.') : (token.slice(0,4) + "*****************");
							req._authorizedScopes = usercache[token] = data.scopes;
	
							next();
						});
					}
				}
				else {
					throw {
						status: 401,
						message: "Invalid Credentials."
					}
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

		// Flat out skip authorization requests in Client mode.
		if (mode == "client") {
			next();
		}

		if (req._authorizedScopes) return res.send({
			name: req._username,
			permissions: req._authorizedScopes
		});

		throw {
			status: 401,
			message: 'Authorization could not be established.',
		};
	});

	return router;
};

/**
 * 
 * @param permissions 
 */
export const requireAuthorization = (permissions: Array<string> = []) => {
    return (req: any, res, next) => {
		if (!req._authorizedScopes) {
            throw {
                status: 401,
                message: 'Authorization credentials not provided.',
            };
		}

        const userScopes = req._authorizedScopes;
        const missingScopes = permissions.filter(p => !userScopes.includes(p));

        // We have all of the scopes we need.
        if (missingScopes.length == 0) {
            return next();
        } 
        // We aren't allowed to do this.
        else {
            throw {
                status: 403,
                message: 'User does not have authorization to access this resource.'
            };
        }
	};
}