const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql'); // arquivo com conexão mysql2/promise

const app = express();
// Usa a porta fornecida pelo ambiente de deploy (como o Render) ou a porta 3000 localmente
const port = process.env.PORT || 3000; 
const mailboxApiKey = 'e37b7fc9c000be253433294d102f9622'; // sua API key Mailboxlayer

// Sessão
app.use(session({
  secret: 'mysecretkey', // Para produção, use uma chave mais segura e do ambiente
  resave: false,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));

// Configuração das Views (EJS) e arquivos estáticos (CSS)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Rota da página inicial
app.get('/', (req, res) => {
  if (req.session.email) {
    console.log('Usuário logado:', req.session.email);
    return res.render('logado');
  }
  
  // CORREÇÃO: Sempre envia um objeto com 'query' e 'erro' para a view.
  res.render('index', {
    erro: null,   // sem erro ao abrir a página
    query: req.query || {}
  });
});

// Rota de Login
app.post('/', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ? AND password = ?', [email, password]);

    if (rows.length > 0) {
      req.session.email = rows[0].email;
      return res.render('logado');
    } else {
      // Envia a mensagem de erro para a view.
      const viewData = {
        erro: 'E-mail ou senha incorretos',
        query: req.query
      };
      return res.render('index', viewData);
    }
  } catch (err) {
    console.error('Erro no banco:', err.message);
    res.status(500).send('Erro no banco de dados');
  }
});

// Rota da página de cadastro
app.get('/register', (req, res) => {
  res.render('register');
});

// Rota de Cadastro
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).send('Preencha o e-mail e a senha');

  const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailValido) return res.status(400).send('Formato de e-mail inválido');

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
    if (!data.format_valid || !data.mx_found || data.disposable) {
        return res.status(400).send('Este endereço de e-mail não é válido ou não é permitido.');
    }

    // Inserir no MySQL
    try {
      await db.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, password]);
      // Redireciona para a página de login com um parâmetro de sucesso na URL
      res.redirect('/?cadastro=sucesso');
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).send('Este e-mail já está cadastrado');
      }
      console.error('Erro ao cadastrar:', err.message);
      res.status(500).send('Erro ao cadastrar usuário');
    }

  } catch (err) {
    console.error('Erro na API:', err.message);
    res.status(500).send('Erro ao verificar o e-mail. Tente novamente.');
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