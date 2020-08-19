const mongoose = require('mongoose')

const AccountSchema = mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  }
});

module.exports = mongoose.model('Account', AccountSchema)
