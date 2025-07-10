const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql'); // arquivo com conexão mysql2/promise

const app = express();
const port = process.env.PORT || 3000; // Usa a porta do ambiente de deploy
const mailboxApiKey = 'e37b7fc9c000be253433294d102f9622'; // sua API key Mailboxlayer

// Sessão
app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));

// Views e estáticos
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Página inicial
app.get('/', (req, res) => {
  if (req.session.email) {
    console.log('Usuário logado:', req.session.email);
    return res.render('logado');
  }
  
  // Objeto de dados para a view. Garante que 'query' e 'erro' sempre existam.
  const viewData = {
    query: req.query,
    erro: null
  };
  
  res.render('index', viewData);
});

// Login
app.post('/', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ? AND password = ?', [email, password]);

    if (rows.length > 0) {
      req.session.email = rows[0].email;
      return res.render('logado');
    } else {
      // Objeto de dados para a view em caso de erro no login.
      const viewData = {
        erro: 'E-mail ou senha incorretos',
        query: req.query
      };
      return res.render('index', viewData);
    }
  } catch (err) {
    console.error('Erro no banco:', err.message);
    res.send('Erro no banco de dados');
  }
});

// Página de cadastro
app.get('/register', (req, res) => {
  res.render('register');
});

// Cadastro
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.send('Preencha o e-mail e a senha');

  const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailValido) return res.send('Formato de e-mail inválido');

  try {
    const response = await axios.get('http://apilayer.net/api/check', {
      params: {
        access_key: mailboxApiKey,
        email: email,
        smtp: 1,
        format: 1
      }
    });

    const data = response.data;
    console.log('Resposta da API:', data);

    if (!data.format_valid) return res.send('E-mail com formato inválido');
    if (!data.mx_found) return res.send('Domínio de e-mail inválido');
    if (data.disposable) return res.send('E-mails temporários não são permitidos');

    // Inserir no MySQL
    try {
      await db.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, password]);
      // Redireciona para a página de login com um parâmetro de sucesso na URL
      res.redirect('/?cadastro=sucesso');
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.send('Este e-mail já está cadastrado');
      }
      console.error('Erro ao cadastrar:', err.message);
      res.send('Erro ao cadastrar usuário');
    }

  } catch (err) {
    console.error('Erro na API:', err.message);
    res.send('Erro ao verificar o e-mail. Tente novamente.');
  }
});

// Rota de Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Não foi possível fazer logout.');
    }
    res.redirect('/');
  });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});