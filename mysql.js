const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'simai-db-instance.cdmwaesa0i63.sa-east-1.rds.amazonaws.com',
  user: 'admin',
  password: '*Juanpablo88',
  database: 'login_db', // troque se o nome for diferente no seu RDS
  port: 3306
});

module.exports = pool.promise();
