const mysql = require("mysql2");

const db = mysql.createConnection({
    host: "localhost",
    user: "root", // Replace with your MySQL username
    password: "Mzy20020212", // Replace with your MySQL password
    database: "accountForStudent", // Your database name
});

db.connect((err) => {
    if (err) throw err;
    console.log("Connected to MySQL database!");
});
