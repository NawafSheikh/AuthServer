const mongoose = require('mongoose')

const DataSchema = mongoose.Schema({
  accountId: {
    type: String,

  },
  class: {
    type: Number,
    required: true
  },
  subject: {
    type: String,
    required: true
  },
  marks: {
    type: Number,
    required: true
  }
});

module.exports = mongoose.model('Data', DataSchema)
