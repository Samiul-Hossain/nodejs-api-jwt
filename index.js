const express = require('express')
const app = express()
const mongoose = require('mongoose')
const dotenv = require('dotenv')

const authRoute = require('./routes/auth')

dotenv.config()

//connect to db
mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () =>
  console.log('connected to db!')
)

//Middleware
app.use(express.json())

app.use('/api/user', authRoute)

app.listen(3000, () => console.log(`Server running on port 3000`))
