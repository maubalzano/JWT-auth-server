require('dotenv').config()

const express = require('express');
const cors = require('cors');
const app = express();
const jwt = require('jsonwebtoken');

const bcrypt = require('bcrypt')

app.use(cors())
app.use(express.json());

let users = [];
let posts = ['Dio è una merda', 'La Madonna è una bagascia', 'Dio e cane sono sinonimi', 'Mannaggia Gesù mannaggia'];
let infos = ['Simone Russo', 'Serena Russo'];
let refreshTokens = [];

app.get('/users', (req, res) => {
    res.json(users)
})

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts)
})

app.get('/infos', authenticateToken, (req, res) => {
    res.json(infos)
})

app.post('/users', async (req, res) => {
    try {
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        const user = {username: req.body.username, password: hashedPassword}
        users = [...users, user];
        res.status(201).send()
    } catch {
        res.status(500).send()
    }
})

app.post('/users/token', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err,user) => {
        if (err) return sendStatus(403)
        const accessToken = generateAccessToken({username: user.username})
        res.json({accessToken:accessToken})
    })
})
app.post('/users/login', async (req,res) => {

    const user = users.find(user => user.username == req.body.username);
    console.log(user)
    if (!user) {
        res.status(400).send(`Cannot find user with username ${req.body.username}`)
    } else {
        
            try {
                if(await bcrypt.compare(req.body.password, user.password)) {
        
                    const accessToken = generateAccessToken(user);
                    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
                    refreshTokens = [...refreshTokens, refreshToken];
                    res.json({accessToken: accessToken, refreshToken: refreshToken})
                } else {
                    res.send('Not allowed')
                }
        
            } catch {
                res.status(500).send()
            }

    }
})

app.delete('/users/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(refTok => refTok != req.body.token)
    res.sendStatus(204)
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(401)
        req.user = user
        next()
    })
}

function generateAccessToken(user) {
    return jwt.sign({username: user.username}, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s'})
}

app.get('/login')
app.listen(3000)

// per SECRET:
// node > require('crypto').randomBytes(64).toString('hex')