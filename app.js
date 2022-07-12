const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const express = require('express');

const app = express();
const bodyParser = require('body-parser');
const auth = require('./auth');

const dbConnect = require('./db/dbConnect');
const User = require('./db/userModel');

dbConnect();

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content, Accept, Content-Type, Authorization',
  );
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, DELETE, PATCH, OPTIONS',
  );
  next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', (request, response, next) => {
  response.json({ message: 'Hey! This is your server response!' });
  next();
});

app.post('/register', (req, res) => {
  bcrypt.hash(req.body.password, 10)
    .then((hashedPassword) => {
      const user = new User({
        email: req.body.email,
        password: hashedPassword,
      });
      user.save().then((result) => {
        res.status(201).send({
          message: 'User Created Successfully',
          result,
        });
      })
        .catch((err) => {
          res.status(500).send({
            message: 'Error creating user',
            err,
          });
        });
    })
    .catch((e) => {
      res.status(500).send({
        message: 'Password was not hashed successfully',
        e,
      });
    });
});

app.post('/login', (req, res) => {
  User.findOne({ email: req.body.email })
    .then((user) => {
      bcrypt.compare(req.body.password, user.password)
        .then((passwordCheck) => {
          if (!passwordCheck) {
            return res.status(400).send({
              message: 'Passwords does not match',
              // err,
            });
          }
          const token = jwt.sign(
            {
              userId: user.id,
              userEmail: user.email,
            },
            'RANDOM-TOKEN',
            { expiresIn: '24h' },
          );
          res.status(200).send({
            message: 'Login Successful',
            email: user.email,
            token,
          });
        })
        .catch((err) => {
          res.status(400).send({
            message: 'Passwords does not match',
            err,
          });
        });
    })
    .catch((e) => {
      res.status(404).send({
        message: 'Email not found',
        e,
      });
    });
});

app.get('/free-endpoint', (req, res) => {
  res.json({ message: 'You are free to access me anytime' });
});

app.get('/auth-endpoint', auth, (req, res) => {
  res.json({ message: 'You are authorized to access me' });
});

module.exports = app;
