const User = require('../model/user');
const jwt = require('jsonwebtoken');
// sendgrid
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

exports.signup = async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const user = await User.findOne({ email }).exec();

        if (user) {
            return res.status(400).json({
                error: 'Email is taken'
            });
        }

        const token = jwt.sign({ name, email, password }, process.env.JWT_ACCOUNT_ACTIVATION, { expiresIn: '10m' });

        const emailData = {
            from: process.env.EMAIL_FROM,
            to: email,
            subject: 'Account activation link',
            html: `
        <h1>Please use the following link to activate your account</h1>
        <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
        <hr />
        <p>This email may contain sensitive information</p>
        <p>${process.env.CLIENT_URL}</p>
      `
        };

        await sgMail.send(emailData);

        return res.json({
            message: `Email has been sent to ${email}. Follow the instructions to activate your account`
        });
    } catch (err) {
        return res.status(500).json({
            error: err.message
        });
    }
};

exports.accountActivation = (req, res) => {
    const { token } = req.body;

    if (token) {
        jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, async (err, decoded) => {
            if (err) {
                console.log('JWT VERIFY IN ACCOUNT ACTIVATION ERROR', err);
                return res.status(401).json({
                    error: 'Expired link. Signup again'
                });
            }

            const { name, email, password } = jwt.decode(token);

            try {
                const user = await User.findOne({ email }).exec();

                if (user) {
                    return res.status(400).json({
                        error: 'User already exists'
                    });
                }

                const newUser = new User({ name, email, password });
                await newUser.save();

                return res.json({
                    message: 'Signup success! Please sign in.'
                });
            } catch (err) {
                console.log('SAVE USER IN ACCOUNT ACTIVATION ERROR', err);
                return res.status(500).json({
                    error: 'Error saving user in database. Try signing up again!'
                });
            }
        });
    } else {
        return res.status(400).json({
            error: 'Something went wrong. Try again.'
        });
    }
};

exports.signin = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email }).exec();

        if (!user) {
            return res.status(400).json({
                error: 'User with that email does not exist. Please signup'
            });
        }

        if (!user.authenticate(password)) {
            return res.status(400).json({
                error: 'Email and password do not match'
            });
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        const { _id, name, role } = user;

        return res.json({
            token,
            user: { _id, name, email, role }
        });
    } catch (err) {
        return res.status(500).json({
            error: err.message
        });
    }
};
