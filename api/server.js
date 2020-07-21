const express = require('express');
const helmet = require('helmet');
const session = require('express-session'); // library
const bcryptjs = require('bcryptjs');
const KnexSessionStore = require('connect-session-knex')(session); //way to connect to db

const usersRouter = require('../users/users-router.js');
const authenticate = require('../auth/authenticate-middleware.js');
const dbConnection = require('../database/connection');
const Users = require('../users/users-model.js');

const server = express();

const sessionConfiguration = {
  name: 'afternoon', // default value is SID (session ID) but don't use it
  secret: process.env.SESSION_SECRET || 'keep it secret, keep it safe!', // key for encryption
  cookie: {
    maxAge: 1000 * 60 * 5, // 1 ms, *60 for 1 sec, *10 for 10 min
    secure: process.env.USE_SECURE_COOKIES || false, // during dev it can be false, but not when it's live
    httpOnly: true, // prevent client JS code from accessing authentication cookie
  },
  resave: false,
  saveUninitiailized: true, // only in dev -- GDPR compliance. this is set after user clicks accept on cookies
  store: new KnexSessionStore({
    knex: dbConnection, // how it connects to the db so it can save info there
    tablename: 'sessions', // table to store info in
    sidfieldname: 'sid',
    createtable: true, // if the table doesn't exist, this creates it
    clearInterval: 1000 * 60 * 30, // how often it will check and remove expired sessions from db (every 30 min in this case)
  }),
};

server.use(session(sessionConfiguration)); // enables session support
server.use(helmet());
server.use(express.json());

server.use('/api/users', authenticate, usersRouter);

server.post('/api/register', (req, res) => {
  let credentials = req.body;
  const hash = hashString(credentials.password);
  credentials.password = hash;
  Users.add(credentials)
    .then((saved) => {
      res.status(201).json({ data: saved });
    })
    .catch((err) => {
      if (err.message.includes('UNIQUE constraint failed')) {
        res.status(500).json({ message: 'That username is already in use.' });
      } else {
        res.status(500).json({ error: err.message });
      }
    });
});

server.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  Users.findBy({ username })
    .then((users) => {
      const user = users[0];
      if (user && bcryptjs.compareSync(password, user.password)) {
        req.session.loggedIn = true;
        req.session.username = user.username;
        res.status(200).json({ message: 'Welcome!' });
      } else {
        res
          .status(401)
          .json({ message: 'Invalid credentials, please try again' });
      }
    })
    .catch((err) => {
      res.status(500).json({ error: err.message });
    });
});

function hashString(str) {
  const rounds = process.env.HASH_ROUNDS || 4;
  return bcryptjs.hashSync(str, rounds);
}

module.exports = server;

//   router.get('/logout', (req, res) => {
//     if (req.session) {
//       req.session.destroy((err) => {
//         if (err) {
//           res
//             .status(500)
//             .json({ message: 'Error logging out, please try again.' });
//         } else {
//           res.status(204).end();
//         }
//       });
//     } else {
//       res.status(200).json({ message: 'Already logged out.' });
//     }
//   });
