
var async = require('async')
var bodyParser = require('body-parser')
var Cookies = require('cookies')
var express = require('express')
var fs = require('fs')
var Handlebars = require('handlebars')
var renderReadme = require('render-readme')
var Search = require('./search')
var Middleware = require('./middleware')
var passport = require('passport')
var OAuth2Strategy = require('passport-oauth2').Strategy;
var Promise = require('bluebird');
var session = require('express-session');
var got = require('got');
var match = Middleware.match
var validate_name = Middleware.validate_name
var validate_pkg = Middleware.validate_package

module.exports = function(config, auth, storage) {
    var app = express.Router()
    var can = Middleware.allow(auth)
    var githubApiUrl = config.oauth2.github_api_url;
    var organization = config.oauth2.org;

    // validate all of these params as a package name
    // this might be too harsh, so ask if it causes trouble
    app.param('package', validate_pkg)
    app.param('filename', validate_name)
    app.param('version', validate_name)
    app.param('anything', match(/.*/))

    passport.use(new OAuth2Strategy({
        authorizationURL: config.oauth2.authorization_url,
        tokenURL: config.oauth2.token_url,
        clientID: config.oauth2.client_id,
        clientSecret: config.oauth2.client_secret,
        callbackURL: config.oauth2.authorization_callback_url,
        scopes: config.oauth2.scopes
    },
    function(accessToken, refreshToken, profile, cb) {
        Promise.all([
            got(githubApiUrl + '/user', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'https://localhost:4873',
                    'Authorization': 'Bearer ' + accessToken
                }
            }),
            got(githubApiUrl + '/user/orgs', {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'https://localhost:4873',
                    'Authorization': 'Bearer ' + accessToken
                }
            })
        ])
        .then(function(responses) {
            var userResponse = responses[0];
            var userOrgsResponse = responses[1];
            var userBody = JSON.parse(userResponse.body);
            var userOrgsBody = JSON.parse(userOrgsResponse.body);

            // Check orgs
            var orgs = userOrgsBody.map(function(userOrg) {
                return userOrg.login;
            });

            if (orgs.indexOf(organization) === -1) {
                cb(new Error('you are not a member of organization ' + organization));
            }

            cb(null, userBody.login);
        })
        .catch(function(err) {
            cb(err);
        });
    }));

    app.use(Cookies.express())
    app.use(bodyParser.urlencoded({
        extended: false
    }))
    app.use(auth.cookie_middleware())
    app.use(session({
        secret: 'keyboard dog'
    }));
    app.use(passport.initialize());
    app.use(passport.session());
    passport.serializeUser(function(user, done) {
        done(null, user);
    });
    passport.deserializeUser(function(user, done) {
        done(null, user);
    });
    app.use(function(req, res, next) {
        // disable loading in frames (clickjacking, etc.)
        res.header('X-Frame-Options', 'deny')
        next()
    })

    Search.configureStorage(storage)

    if (config.web && config.web.template) {
        var template = Handlebars.compile(fs.readFileSync(config.web.template, 'utf8'));
    } else {
        Handlebars.registerPartial('entry', fs.readFileSync(require.resolve('./GUI/entry.hbs'), 'utf8'))
        var template = Handlebars.compile(fs.readFileSync(require.resolve('./GUI/index.hbs'), 'utf8'))
    }
    app.get('/', function(req, res, next) {
        res.render('index');
    })

    app.get('/home', isLoggedIn, function(req, res, next) {
        var base = config.url_prefix ?
            config.url_prefix.replace(/\/$/, '') :
            req.protocol + '://' + req.get('host')
        res.setHeader('Content-Type', 'text/html')

        storage.get_local(function(err, packages) {
            if (err) throw err // that function shouldn't produce any
            async.filterSeries(packages, function(package, cb) {
                auth.allow_access(package.name, req.remote_user, function(err, allowed) {
                    setImmediate(function() {
                        cb(!err && allowed)
                    })
                })
            }, function(packages) {
                packages.sort(function(p1, p2) {
                    if (p1.name < p2.name) {
                        return -1;
                    } else {
                        return 1;
                    }
                });
                res.render('home', {
                    content: template({
                        name:       config.web && config.web.title ? config.web.title : 'Nexxtopia',
                        packages:   packages,
                        baseUrl:    base,
                        username:   req.remote_user.name,
                    })
                });
            })
        });
    });

    // route for logging out
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });

    // facebook routes
    // twitter routes

    // =====================================
    // GOOGLE ROUTES =======================
    // =====================================
    // send to google to do the authentication
    // profile gets us their basic information including their name
    // email gets their emails
    app.get('/auth/github', passport.authenticate('oauth2'));

    // the callback after google has authenticated the user
    app.get(
        '/auth/github/callback',
        passport.authenticate('oauth2', {
            successRedirect : '/home',
            failureRedirect : '/'
        })
    );

    // route middleware to make sure a user is logged in
    function isLoggedIn(req, res, next) {

        // if user is authenticated in the session, carry on
        if (req.isAuthenticated())
            return next();

        // if they aren't redirect them to the home page
        res.redirect('/auth/github');
    }

    // Static
    app.get('/-/static/:filename', function(req, res, next) {
        var file = __dirname + '/static/' + req.params.filename
        res.sendFile(file, function(err) {
            if (!err) return
            if (err.status === 404) {
                next()
            } else {
                next(err)
            }
        })
    })

    app.get('/-/logo', function(req, res, next) {
        res.sendFile(config.web && config.web.logo ?
            config.web.logo :
            __dirname + '/static/logo-sm.png')
    })

    app.post('/-/login', function(req, res, next) {
        auth.authenticate(req.body.user, req.body.pass, function(err, user) {
            if (!err) {
                req.remote_user = user
                    //res.cookies.set('token', auth.issue_token(req.remote_user))

                var str = req.body.user + ':' + req.body.pass
                res.cookies.set('token', auth.aes_encrypt(str).toString('base64'))
            }

            var base = config.url_prefix ?
                config.url_prefix.replace(/\/$/, '') :
                req.protocol + '://' + req.get('host')
            res.redirect(base)
        })
    })

    app.post('/-/logout', function(req, res, next) {
        var base = config.url_prefix ?
            config.url_prefix.replace(/\/$/, '') :
            req.protocol + '://' + req.get('host')
        res.cookies.set('token', '')
        res.redirect(base)
    })

    // Search
    app.get('/-/search/:anything', can('access'), function(req, res, next) {
        var results = Search.query(req.params.anything)
        var packages = []

        var getData = function(i) {
            storage.get_package(results[i].ref, function(err, entry) {
                if (!err && entry) {
                    packages.push(entry.versions[entry['dist-tags'].latest])
                }

                if (i >= results.length - 1) {
                    next(packages)
                } else {
                    getData(i + 1)
                }
            })
        }

        if (results.length) {
            getData(0)
        } else {
            next([])
        }
    })

    app.get('/-/readme/:package/:version?', can('access'), function(req, res, next) {
        storage.get_package(req.params.package, {
            req: req
        }, function(err, info) {
            if (err) return next(err)
            next(renderReadme(info.readme || 'ERROR: No README data found!'))
        })
    })
    return app
}
