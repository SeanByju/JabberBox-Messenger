const BaseJoi = require('joi');
const sanitizeHtml = require('sanitize-html');

const extention = (joi)=> ({
    type: 'string',
    base: joi.string(),
    messages: {
        'string.escapeHTML': '{{#label}} must not include HTML!'
    },
    rules: {
        escapeHTML: {
            validate(value, helpers){
                const clean = sanitizeHtml(value, {
                    allowedTags: [],
                    allowedAttributes: {},
                });
                if(clean !== value) return helpers.error('string.escapeHTML', {value})
                return clean
            }
        }
    }
});

const Joi = BaseJoi.extend(extention);

module.exports.userSchema = Joi.object({    
    username: Joi.string().alphanum().min(6).max(30).required(),
    email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required(),
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required(),
}).required()

