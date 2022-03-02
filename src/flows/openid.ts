import { auth } from 'express-openid-connect';

export const OpenId = (router, cache, options) => {
    // Customize session store to share sessions across the process instances.
    if (!options)
        options = {};
    if (!options.session)
        options.session = {};
    options.session.store = {
        get: (id, done) => {
            cache.get(id)
                .then(res => done(null, res))
                .catch(err => done(err));
        },
        set: (id, session, done) => {
            cache.put(id, session)
                .then(res => done(null))
                .catch(err => done(err));
        },
        destroy: (id, done) => {
            cache.delete(id)
                .then(res => done(null))
                .catch(err => done(err));
        }
    };
    // This MUST BE SET.
    options.routes = {
        login: "/login/openid",
        logout: "/logout/openid",
        postLogoutRedirect: "/",
        callback: "/code/openid"
    };
    router.use(auth(options));
    router.use((req, res, next) => {
        if (req.oidc && req.oidc.user)
            req._username = req.oidc.user.upn;
        next();
    });
};
