const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql'); // conexão com MySQL
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 3000;

// Configuração do Nodemailer (Gmail com senha de app)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'bandeiradiogo96@gmail.com', // seu Gmail
    pass: 'hwbk edim tmwb lxmv' // sua senha de app
  }
});

// Função para enviar e-mail
async function enviarEmail(destinatario, assunto, mensagem) {
  try {
    const info = await transporter.sendMail({
      from: '"Meu Site" <bandeiradiogo96@gmail.com>',
      to: destinatario,
      subject: assunto,
      text: mensagem
    });
    console.log('E-mail enviado: %s', info.messageId);
  } catch (erro) {
    console.error('Erro ao enviar e-mail:', erro.message);
  }
}


// Suas chaves
const mailboxApiKey = 'e37b7fc9c000be253433294d102f9622'; // Mailboxlayer
const recaptchaSecret = '6Leu9H4rAAAAAHlL0O_fcrJe4i1AgaXW_tPjduUs'; // reCAPTCHA (SECRET KEY)

// Sessão
app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));

// Views e estáticos
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Página inicial
app.get('/', (req, res) => {
  if (req.session.email) {
    console.log('Usuário logado:', req.session.email);
    return res.render('logado');
  }

  res.render('index', {
    erro: null,
    query: req.query || {}
  });
});

// Login
app.post('/', async (req, res) => {
  const { email, password, 'g-recaptcha-response': captcha } = req.body;

  // Verifica se marcou o captcha
  if (!captcha) {
    return res.render('index', {
      erro: 'Por favor, confirme que você não é um robô.',
      query: {}
    });
  }

  // Verifica com o Google reCAPTCHA
  try {
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${recaptchaSecret}&response=${captcha}`;
    const response = await axios.post(verifyUrl, null, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const data = response.data;

    if (!data.success) {
      return res.render('index', {
        erro: 'Falha na verificação do reCAPTCHA.',
        query: {}
      });
    }

    // Validação de login
    const [rows] = await db.execute(
      'SELECT * FROM users WHERE email = ? AND password = ?', [email, password]
    );

    if (rows.length > 0) {
      req.session.email = rows[0].email;
      return res.render('logado');
    } else {
      return res.render('index', {
        erro: 'E-mail ou senha incorretos',
        query: {}
      });
    }

  } catch (err) {
    console.error('Erro ao verificar reCAPTCHA:', err.message);
    return res.status(500).send('Erro ao verificar reCAPTCHA');
  }
});

// Página de cadastro
app.get('/register', (req, res) => {
  res.render('register');
});

// Cadastro
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

    try {
      await db.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, password]);

        // Envia e-mail de boas-vindas
        await enviarEmail(email, 'Bem-vindo!', 'Seu cadastro foi realizado com sucesso!');

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

// Logout
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
