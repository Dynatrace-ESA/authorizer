import { dynatraceTokenRegex } from "@dt-esa/platform-constants";
import axios from 'axios';
import https from 'https';

function getTokenPermissions(dtUrl, token, customAxios = axios) {
    return customAxios.post(dtUrl + `api/v1/tokens/lookup`, { token }, {
        httpsAgent: new https.Agent({
            rejectUnauthorized: false
        }),
        headers: {
            Authorization: "Api-Token " + token
        }
    });
}

export const Dynatrace = (router, usercache, options) => {
    router.use((req, res, next) => {
        const authHeader = req.header('Authorization');

        // If the token isn't "basic" -- pass it to whatever client may be using it.
        if (!authHeader || /^api-token /i.test(authHeader))
            return next();

        // If there is some other use for the Authorization header (NOT `BASIC`).
        if (!/^basic /i.test(authHeader))
            return next();

        const auth = authHeader.replace(/^basic /i, '');
        const token = Buffer.from(auth, 'base64').toString();

        // Quickly check that the token is in Dynatrace format.
        if (dynatraceTokenRegex.test(token)) {

            // TODO: setup expiration for cache
            // If we have a token AND it's been cached for longer than 30 minutes, purge it.
            // This keeps us from caching tokens indefinitely.
            // if (usercache[token] &&
            //     ((new Date().getTime() - usercache[token]._storeTime) > 30 * 60 * 1000)) {
            //     delete usercache[token];
            // }
            const tokenId = token.length > 40 ? token.split('.').slice(0, 2).join('.') : (token.slice(0, 4) + "*****************");

            try {
                usercache.get(tokenId).then(userScopes => {
                    // If the user isn't cached, it will return 'undefined'.
                    if (userScopes) {
                        // Decorate request.
                        req._username = tokenId;
                        req._authorizedScopes = userScopes;
                        req._scopeMapping = options.scopeMappings; // !
                        return next();
                    }
                    else {
                        let dtUrl = options.endpoint;
                        if (!dtUrl.endsWith('/'))
                            dtUrl += '/';
                        if (!dtUrl.startsWith('https://'))
                            dtUrl = "https://" + dtUrl;

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
                            usercache.put(tokenId, data.scopes);
                            
                            // Decorate Request.
                            req._username = tokenId;
                            req._authorizedScopes = data.scopes;
                            req._scopeMapping = options.scopeMappings;

                            next();
                        }).catch(err => {
                            next({
                                status: 500,
                                message: "Failed to lookup token",
                                stack: err.stack,
                                ex: err
                            });
                        });
                    }
                });
            }
            catch (ex) {
                next(ex);
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
};
