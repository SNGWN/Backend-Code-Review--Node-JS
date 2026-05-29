const express = require('express');
const { exec } = require('./a');

const app = express();
app.post('/run', (req, res) => {
  exec(req.body.cmd, (_err, stdout) => res.send(stdout));
});

module.exports = app;
