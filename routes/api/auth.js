const express = require('express');
const auth = require('../../middleware/auth');
const Users = require('../../models/Users');
const router = express.Router();
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

// @route   Get api/auth
// @desc    Test route
// @access  Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await Users.findById(req.user.id).select('-password');
        res.json(user);
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   POST api/auth
// @desc    Authenticate user & get token
// @access  Public
router.post('/', [
    check('email', 'Please include a valid email')
        .isEmail(),
    check('password', 'Password is required')
        .exists()
    ], 
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {

            let user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({ errors: [ { msg: 'Invalid credentials'}] });
            }

            const isMatch = await bcrypt.compare(password, user.password);

            if (!isMatch) {
                return res.status(400).json({ errors: [ { msg: 'Invalid credentials'}] });
            }

            const payload = {
                user: {
                    id: user.id,
                    email: email
                }
            }

            jwt.sign( 
                payload, 
                config.get('jwtSecret'), 
                {expiresIn: 36000000}, 
                (err, token) => {
                    if(err) throw err;
                    res.json({token});
                }   
            );

        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }
    }
);


module.exports = router;