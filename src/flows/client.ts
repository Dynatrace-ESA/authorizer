import axios from 'axios';
import https from 'https';

export const Client = (router, options) => {
    router.use((req, res, next) => {
        // Pass if we don't have a session
        if (!req.cookies["connect.sid"])
            return next();
        axios
            .get(`https://127.0.0.1:${options.port}/authorization`, {
            httpsAgent: new https.Agent({
                rejectUnauthorized: false
            }),
            headers: {
                Cookie: `connect.sid=` + req.cookies['connect.sid']
            },
        })
            .then(response => {
            const data = response.data;
            // If we have authorizations specified in client mode, then join them with the 
            // authorizations specified from the server.
            const locallyAppliedPermissions = options.authorizations
                ? options.authorizations[data.name]
                : [] || []; // Always default as an empty array.
            req._username = data.name.toLowerCase();
            req._authorizedScopes = data.permissions.concat(locallyAppliedPermissions);
            return next();
        });
    });
};
