const Raven = require('raven')
const cel = require('connect-ensure-login')
const router = require('express').Router()

const models = require('../../db/models').models;
const mail = require('../../utils/email')
const {findUserByParams} = require('../../controllers/user')
const {createAndSendOTP} = require('../../controllers/verify_otp')
const passport = require('../../passport/passporthandler')

const debug = require('debug')('login_using_otp:routes:login_otp')

// We do not handle get requests on this path at all
router.get('/', (req, res) => {
    res.redirect('/login')
})

router.post('/', cel.ensureNotLoggedIn('/'), async (req, res, next) => {
    try {

        if (req.body.password) {
            passport.authenticate('otp', function (err, user, info) {
                if (err) {
                    return next(err)
                }
                if (!user) {
                    req.flash('error', 'Incorrect OTP')
                    return res.render('login_otp', {
                        pageTitle: "Login with OTP",
                        username: req.body.username,
                        messages: {
                            error: req.flash('error'),
                            info: req.flash('info')
                        }
                    })
                }
                req.login(user, function (err) {
                    if (err) {
                        return next(err)
                    }
                    return res.redirect('/users/me')
                })
            })(req, res, next)

        } else {
            //creates a 6 digit random number.
            const key = Math.floor(100000 + Math.random() * 900000)

            // Case: Mobile Number 
            let user = await findUserByParams({verifiedmobile: `+91-${req.body.username}`})
            if(user) {

                await models.UserMobileOTP.upsert({
                    mobile_number: user.dataValues.mobile_number,
                    login_otp: key,
                    userId: user.dataValues.id,
                    include: [models.User]
                })

                createAndSendOTP(user.mobile_number, key, 'accessing your Coding Blocks Account')
                .then(function (body) {
                    debug(body)
                }).catch(function (error) {
                    throw new Error(error)
                })

                req.flash('info', 'We have sent you an OTP on your number')
                res.render('login_otp', {
                    pageTitle: "Login with OTP",
                    username: req.body.username,
                    messages: {
                        error: req.flash('error'),
                        info: req.flash('info')
                    }
                })

            } else {
                // Case: Email Address
                user = await findUserByParams({verifiedemail: req.body.username})
                if(user) {
            
                    await models.UserEmailOTP.upsert({
                        email: user.dataValues.email,
                        login_otp: key,
                        userId: user.dataValues.id,
                        include: [models.User]
                    })

                    await mail.verifyOTPEmail(user, key)

                    req.flash('info', 'We have sent you an OTP on your email address')
                    res.render('login_otp', {
                        pageTitle: "Login with OTP",
                        username: user.dataValues.email,
                        messages: {
                            error: req.flash('error'),
                            info: req.flash('info')
                        }
                    })

                } else {
                    // Invalid Input
                    req.flash('error', 'Please enter a verified mobile number or a verified email.')
                    return res.redirect('/')
                }
            }
        }
    } catch (e) {
        Raven.captureException(e)
        req.flash('error', 'Error logging in with OTP.')
        res.redirect('/')
    }

})


router.post('/resend', cel.ensureNotLoggedIn('/'), async (req, res, next) => {
    try {
        //creates a 6 digit random number.
        const key = Math.floor(100000 + Math.random() * 900000)

        // Case: Mobile Number 
        let user = await findUserByParams({verifiedmobile: `+91-${req.body.username}`})
        if(user) {

            await models.UserMobileOTP.upsert({
                mobile_number: user.dataValues.mobile_number,
                login_otp: key,
                userId: user.dataValues.id,
                include: [models.User]
            })

            createAndSendOTP(user.mobile_number, key, 'accessing your Coding Blocks Account')
            .then(function (body) {
                debug(body)
            }).catch(function (error) {
                throw new Error(error)
            })

            req.flash('info', 'We have sent you an OTP on your number')
            res.render('login_otp', {
                pageTitle: "Login with OTP",
                username: req.body.username,
                messages: {
                    error: req.flash('error'),
                    info: req.flash('info')
                }
            })

        } else {
            // Case: Email Address
            user = await findUserByParams({verifiedemail: req.body.username})
            if(user) {
                await models.UserEmailOTP.upsert({
                    email: user.dataValues.email,
                    login_otp: key,
                    userId: user.dataValues.id,
                    include: [models.User]
                })

                await mail.verifyOTPEmail(user, key)

                req.flash('info', 'We have sent you an OTP on your email address')
                res.render('login_otp', {
                    pageTitle: "Login with OTP",
                    username: user.dataValues.email,
                    messages: {
                        error: req.flash('error'),
                        info: req.flash('info')
                    }
                })

            } else {
                // Invalid Input
                req.flash('error', 'Please enter a verified mobile number or a verified email.')
                return res.redirect('/')
            }
        }

    } catch (e) {
        Raven.captureException(e)
        req.flash('error', 'Error logging in with OTP.')
        res.redirect('/')
    }


})

module.exports = router