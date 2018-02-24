var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

//Users schema
var usersSchema = new mongoose.Schema({
    first_name: {
        type: String,
        required: [true, "First name field is required."]
    },
    last_name: {
        type: String,
        required: [true, "Last name field is required."]
    },
    gender: String,
    address: {
        street: {
            type: String
        },
        city: {
            type: String
        },
        state: {
            type: String
        }
    },
    age: Number,
    balance: Number,
    
    username: String,
    password: {
        type: String,
        select: false
    }
});

// generate a hash
usersSchema.methods.generateHash = function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// check if password is valid
usersSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model('Users', usersSchema);

/*var commands = {
    getUsers: function(callback) {
        return Users.find(callback);
    },
    getUserById: function(id, callback) {
        return Users.findById(id, callback);
    },
    addUser: function(userObj, callback) {
        return Users.create(userObj, callback);
    },
    updateUser:function(id, userObj, callback) {
        var query = {_id: userObj.id};
        var update = { $set:{
    
        }
    
        };
        Users.set(query, update, userObj, callback);
    }
};*/