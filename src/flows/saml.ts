import {Strategy} from "passport-saml";

export const Saml = (router, cache, options, passport) => {
    // TBD.
    passport.serializeUser((user, done) => {
        done(null, user.nameID);
    });
    
    passport.deserializeUser((key, done) => {
        cache.get(key).then((user) => {
            if (user.ex)
                return done(user.ex);
            done(null, user);
        }).catch(done);
    });

    const strategy = new Strategy(options, (profile: any, done: any) => {
        cache.get(profile.nameID).then((stored) => {
            // Something failed.
            if (stored !== undefined && stored.ex)
                return done(stored);
            // If we don't have the profile in the cache, store it.
            if (stored === undefined)
                cache.put(profile.nameID, profile);
            return done(null, profile);
        }).catch(done);
    });
    passport.use(strategy);

    // ! Redundant.
    // Always try to add the authorized scopes for further processing in the chain.
    router.use((req, res, next) => {
        var _a;
        if (!req._authorizedScopes) {
            const email = (_a = req.user) === null || _a === void 0 ? void 0 : _a.nameID;
            req._username = email.toLowerCase();
        }
        next();
    });

    router.get('/login/saml', (req, res, next) => passport.authenticate("saml", {
        response: res,
        failureRedirect: '/',
    })(req, res, next), (req, res) => {
        res.redirect('/');
    });

    router.use('/code/saml', (req, res, next) => {
        passport.authenticate("saml", {
            response: res,
            failureRedirect: '/',
        })(req, res, next);
    }, (req, res) => {
        res.redirect('/');
    });
};
