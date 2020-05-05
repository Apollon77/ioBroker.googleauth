/* global __dirname */

const path = require('path')
const express = require('express')
var passport = require('passport')
var GoogleStrategy = require('passport-google-oauth20').Strategy

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
            for(let sUserId in oUsers){
               let oUser = oUsers[sUserId]
               if(oUser.common && oUser.common.googleId === profile.id)
                  return done(null, sUserId.split('.')[2])
            }
            
            // No user found, so take the local logged in user and assign google id
            if(!req.user) // no local logged in user? -> error
               return done(null, false, { error: 'Login2Register' })
            
            adapter.extendForeignObject('system.user.' + req.user, {
               common: {
                  googleId: profile.id
               }
            }, (err, oObject) => {
               if(err)
                  return done(err)
               adapter.log.info(instanceSettings.common.name + ': User ' + req.user + ' associated to Google with ID ' + oObject.value.common.googleId)
               done(null, req.user)
            })
         })
      }))
      
      app.use('/login/google/img', express.static(path.join(__dirname, 'www/img')))
      
      app.get('/login(/index.html)?', (req, res, next) => {
         // try to override login screen
         if(req.isAuthenticated())
            return res.redirect((req.query.href)?req.query.href:'/')
         res.sendFile(path.join(__dirname, 'www/views/login.html'))
      })

      app.post('/login/google', (req, res, next) => {
         next(req.body.firsttime?null:'route')
      }, passport.authenticate('local'))
      app.post('/login/google', (req, res, next) => {
         let oRedirectMatch = /(\?|&)href=(\/[-_a-zA-Z0-9%./]*)/.exec(decodeURIComponent(req.body.origin))
         passport.authenticate('google', {
            scope: ['profile'],
            state: (oRedirectMatch)?oRedirectMatch[2]:null  // take value of parameter href from second submatch
         })(req, res, next)
      })
      
      app.get('/login/google/cb', passport.authenticate('google', {
         failureRedirect: '/login'
      }), (req, res) => {
         res.redirect((req.query.state)?req.query.state:'/')
      })
      
      adapter.log.info('Google Authentication is ready')
   }
}

module.exports = WebExtension