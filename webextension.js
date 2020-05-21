/*eslint semi: ["error", "never", { "beforeStatementContinuationChars": "never"}] */
/*eslint quotes: ["error", "single"]*/
/*eslint-env es6*/

const path = require('path')
const express = require('express')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth20').Strategy

const ONE_MONTH_SEC = 30 * 24 * 3600

/**
 * Extension for Web Server
 * Register Google Authentication at passport
 * Provide routes for Google Authentication
 *
 * @class
 * @param {object} server http or https node.js object
 * @param {object} webSettings settings of the web server, like <pre><code>{secure: settings.secure, port: settings.port}</code></pre>
 * @param {object} adapter web adapter object
 * @param {object} instanceSettings instance object with common and native
 * @param {object} app express application
 */
class WebExtension {
   constructor(server, webSettings, adapter, instanceSettings, app) {
      this.config = instanceSettings.native

      passport.use(new GoogleStrategy({
         clientID: this.config.clientId,
         clientSecret: this.config.clientSecret,
         userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
         callbackURL: '/login/google/cb',
         passReqToCallback: true,
         proxy: this.config.proxy
      }, (req, accessToken, refreshToken, profile, done) => {
         // get all users
         adapter.getForeignObjects('system.user.*', 'user', (err, oUsers) => {
            if(err){
               adapter.log.info(instanceSettings.common.name + ': ' + err)
               return done(err)
            }

            // try to find the user with the given google user id
            for(let [sUserId, oUser] of Object.entries(oUsers)){
               if(oUser.common && oUser.common.googleId === profile.id){
                  return done(null, sUserId.split('.')[2])
               }
            }
            
            // No user found, so take the local logged in user and assign google id
            if(!req.user){ // no local logged in user? -> error
               return done(null, false, { error: 'Login2Register' })
            }
            
            adapter.extendForeignObject('system.user.' + req.user, {
               common: {
                  googleId: profile.id
               }
            }, (err, oObject) => {
               if(err){
                  return done(err)
               }
               adapter.log.info(instanceSettings.common.name + ': User ' + req.user + ' associated to Google with ID ' + oObject.value.common.googleId)
               done(null, req.user)
            })
         })
      }))
      
      // provide image for sign in
      app.use('/login/google/img', express.static(path.join(__dirname, 'www/img')))
      
      app.post('/login/google', (req, res, next) => {
         // on first time login handle next middleware (local authentication) in calling chain,
         // otherwise handle immediately next fitting route (google authentication)
         next(req.body.firsttime?null:'route')
      }, passport.authenticate('local'))
      app.post('/login/google', (req, res, next) => {
         let oRedirectMatch = /(\?|&)?href=(\/[-_a-zA-Z0-9%./]*)/.exec(decodeURIComponent(req.body.origin))
         let bStayLoggedIn = req.body.stayloggedin === 'true' || req.body.stayloggedin === true || req.body.stayloggedin === 'on'
         passport.authenticate('google', {
            scope: ['profile'],
            state: JSON.stringify({ 
               href: (oRedirectMatch)?oRedirectMatch[2]:null, // take value of parameter href from second submatch
               stay: bStayLoggedIn
            })
         })(req, res, next)
      })
      
      app.get('/login/google/cb', passport.authenticate('google', {
         failureRedirect: '/login'
      }), (req, res) => {
         let oState = JSON.parse(req.query.state)
         let sTarget = '/'
         if(oState){
            sTarget = oState.href || sTarget
            req.session.cookie.maxAge = webSettings.ttl * 1000
            if(oState.stay && ONE_MONTH_SEC > webSettings.ttl){
               req.session.cookie.maxAge = ONE_MONTH_SEC * 1000
            }
         }
         res.redirect(sTarget)
      })
      
      adapter.log.info('Google Authentication is ready')
   }
}

module.exports = WebExtension