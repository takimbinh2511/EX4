const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const {check, validationResult} = require("express-validator");
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");

const User = require('../../models/User');

// @route  GET api/auth
// @desc   Test route
// @access Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select(('-password'));
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route  POST api/auth
// @desc   Authenticate user & get token
// @access Public
router.post(
    "/",
    [
        check("email", "Please include a valid email").isEmail(),
        check(
            "password",
            "Password is requried"
        ).exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            // if some inf above dont map, it will return here(400 errors)
            return res.status(400).json({errors: errors.array()});
        }

        const { email, password} = req.body;

        try {
            let user = await User.findOne({ email });

            if(!user) {
                res.status(400)
                    .json({ errors: [{ msg: 'Invalid Credentials'}]});
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if(!isMatch) {
                res.status(400)
                    .json({ errors: [{ msg: 'Invalid Credentials'}]});
            }

            // Return jsonwebtoken
            const payload = {
                user: {
                    id: user._id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 36000},
                (err, token) => {
                    if(err) throw err;
                    res.json({ token });
                }
            );
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error')
        }
        console.log(req.body);
    }
);

module.exports = router;