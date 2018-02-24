const express = require('express');
const router = express.Router();
const User = require('../user');

//Retrives all the info about the users in the database.
router.get('/getallusers', (request, response, next) => {
    console.log(`Request made at IP ${request.socket.remoteAddress}:${request.socket.remotePort}`);

    User.find()
    .then(data => { response.json(data) })
    .catch(next);
})

//Retrieves a specific user based on the ID.
router.get('/:_id', (request, response, next) => {
    console.log(`Request made at IP ${request.socket.remoteAddress}:${request.socket.remotePort}`);

    User.findById({_id: request.params._id})
    .then(data => { response.json(data) })
    .catch(next);
})

//Adds a new user into the database.
router.post('/adduser', (request, response, next) => {
    var content = request.body;
    User.create(content)
    .then(data => { response.json(data) })
    .catch(next);
})

router.put('/updateuser', (request, response, next) => {
    User.update()
    .then(data => { response.json(data) })
    .catch(next);
})

module.exports = router;