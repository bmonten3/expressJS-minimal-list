

//initializes all needed libraries for use.
const sqlite3 = require('sqlite3')
const sqlite = require('sqlite')
const express = require('express')
const app = express();
const handlebars = require('express-handlebars');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const port = 8080;


app.engine('handlebars', handlebars.engine())
app.set('view engine', 'handlebars');


app.use(express.static(__dirname + '/static'));
app.use(express.urlencoded({extended: false}));
app.use(cookieParser());

//saltrounds same as recommended from workshop.
const saltRounds = 10;

//promise function to use databse.
const dbPromise = sqlite.open({
    filename: './database/todolist.sqlite',
    driver: sqlite3.Database
});

//authentication middleware function very similar to the one from chuck's tutorial. 
//implementation allows me more functionality pulling certain values out of the tables.
const authMiddleware = async (req, res, next) => {
    if (!req.cookies || !req.cookies.authToken) {
      return next();
    }
    const db = await dbPromise;
    const authToken = await db.get(
      "SELECT * FROM authtokens WHERE token = ?",
      req.cookies.authToken
    );
    if (!authToken) {
      return next();
    }
    const user = await db.get(
      "SELECT user_id, username FROM users WHERE user_id = ?",
      authToken.user_id
    );
    req.user = user;
    next();
  };
  
app.use(authMiddleware);

//handles what happens when user lands on website.
app.get('/', (req,res) => {
    res.render('login',{layout:false})
})
//console log to know what port server is running on
app.listen(port, () => {
    console.log('Server started on port:', port);
})

app.get('/register', (req,res) => {
    res.render('register',{layout:false})
})

//login action from home handlebars
app.post('/login', async (req , res) => {
    const { username, password } = req.body;
    const db = await dbPromise
    
    if (!username || !password) {
        return res.render("login", { error: "All fields are required" });
      }

    try {
        const user = await db.get(
          "SELECT * FROM users WHERE username = ?",
          username
        );
        if (!user) {
          return res.render("login", { error: "Oops! username or password is incorrect." });
        }

        const passwordVerifiion = await bcrypt.compare(password, user.password);

        if (!passwordVerifiion) {
            return res.render("login", {error: "Oops! username or password is incorrect."})
        }

        const authToken = uuidv4();

        await db.run(
            "INSERT INTO authtokens(token, user_id) VALUES (?,?);",
            authToken,
            user.user_id
        );
        res.cookie("authToken", authToken);
    } catch(error) {
        res.render("login", {error: "An error has occurred."})
    }
    res.redirect("/home");
})

app.post('/register', async (req , res) => {

    const { username, password, confirmPassword } = req.body;
    const db = await dbPromise
 
    if (!username || !password || !confirmPassword) {
        return res.render("register",{error: "All fields are required!"})
    }
    if (password != confirmPassword) {
        return res.render("register", {error: "Passwords must match!"})
    }

   
    try {
        const passHash = await bcrypt.hash(password, saltRounds);
        await db.run(
            "INSERT INTO users(username, password) VALUES (?,?);",
            username,
            passHash
        );
        const newUser = await db.get(
            "SELECT * FROM users WHERE username = ?",
            username
        );

        const authToken = uuidv4();

        await db.run(
            "INSERT INTO authtokens(token, user_id) VALUES (?,?);",
            authToken,
            newUser.user_id
        );
        res.cookie("authToken", authToken);
    }
    catch(error) {
        if (error.message === "SQLITE_CONSTRAINT: UNIQUE constraint failed: User.username") {
            return res.render("register", {error: "This username already exists!"});
        }
        return res.render("register", {error: "Oops! An error has occurred!"})
    }
    res.redirect("/home")
});

app.get('/home', async (req, res) => {
    console.log("made it to home")
    //save user id to variable from cookie
    let userid = req.user.user_id
    const db = await dbPromise

    let task_id_query = `SELECT * FROM tasks WHERE user_id=${userid};`
    var task_id_list = await db.all(task_id_query) 
    
    //renders all these variables to placeholders in handlebars files
    res.render('home', {layout:false,
                'username':req.user.username,
                'task_id':task_id_list.task_id,
                'task_desc':task_id_list.task_desc,
                'is_complete':task_id_list.is_complete,
                'tasks':task_id_list});

    

})

app.post('/add_task', async (req, res) => {

    
    const db = await dbPromise
    let user_id = req.user.user_id
    let addTask = `INSERT INTO tasks(user_id,task_desc,is_complete) VALUES (?,?,?)`;
    let taskDesc = req.body.taskDesc

    db.run(addTask, [user_id, taskDesc, false]);
    res.redirect('/home')

})

app.get('/logout', (req, res ) => {
    res.clearCookie("authToken");
    res.redirect('/')
}) 
