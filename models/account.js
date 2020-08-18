const mongoose = require('mongoose')

const AccountSchema = mongoose.Schema({
  name: {
    type: String,
    require: true
  },
  password: {
    type: String,
    require: true
  }
});

module.exports = mongoose.model('Account', AccountSchema)
