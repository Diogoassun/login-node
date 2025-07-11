const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'bandeiradiogo96@gmail.com',
    pass: 'hwbk edim tmwb lxmv'
  }
});

async function enviarEmail(destinatario, assunto, mensagem) {
  try {
    const info = await transporter.sendMail({
      from: '"SMAI" <bandeiradiogo96@gmail.com>',
      to: destinatario,
      subject: assunto,
      text: mensagem
    });
    console.log('E-mail enviado: %s', info.messageId);
  } catch (erro) {
    console.error('Erro ao enviar e-mail:', erro.message);
  }
}

const mailboxApiKey = 'e37b7fc9c000be253433294d102f9622';
const recaptchaSecret = '6Leu9H4rAAAAAHlL0O_fcrJe4i1AgaXW_tPjduUs';

app.use(session({
  secret: 'mysecretkey',
  resave: false,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/', async (req, res) => {
  if (req.session.email) {
    return res.render('logado', { email: req.session.email });
  }
  res.render('index', { erro: null, query: req.query || {} });
});

app.post('/', async (req, res) => {
  const { email, password, 'g-recaptcha-response': captcha } = req.body;

  if (!captcha) return res.render('index', { erro: 'Por favor, confirme que você não é um robô.', query: {} });

  try {
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${recaptchaSecret}&response=${captcha}`;
    const response = await axios.post(verifyUrl);
    if (!response.data.success) return res.render('index', { erro: 'Falha na verificação do reCAPTCHA.', query: {} });

    const [rows] = await db.execute('SELECT * FROM users WHERE email = ? AND password = ?', [email, password]);

    if (rows.length > 0) {
      const user = rows[0];
      if (user.two_factor_enabled) {
        const verificationCode = Math.floor(100000 + Math.random() * 900000);
        req.session.pendingUser = user.email;
        req.session.verificationCode = verificationCode;
        req.session.verificationExpires = Date.now() + 5 * 60 * 1000;

        await enviarEmail(user.email, 'Código de Verificação 2FA', `Seu código de verificação é: ${verificationCode}`);
        return res.redirect('/verify-2fa');
      }
      req.session.email = user.email;
      return res.render('logado', { email: user.email });
    } else {
      return res.render('index', { erro: 'E-mail ou senha incorretos', query: {} });
    }
  } catch (err) {
    console.error('Erro ao verificar reCAPTCHA:', err.message);
    return res.status(500).send('Erro ao verificar reCAPTCHA');
  }
});

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Preencha o e-mail e a senha');
  const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailValido) return res.status(400).send('Formato de e-mail inválido');

  try {
    const response = await axios.get('http://apilayer.net/api/check', {
      params: { access_key: mailboxApiKey, email, smtp: 1, format: 1 }
    });
    const data = response.data;
    if (!data.format_valid || !data.mx_found || data.disposable) {
      return res.status(400).send('Este endereço de e-mail não é válido ou não é permitido.');
    }
    try {
      await db.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, password]);
      await enviarEmail(email, 'Bem-vindo!', 'Seu cadastro foi realizado com sucesso!');
      res.redirect('/?cadastro=sucesso');
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(409).send('Este e-mail já está cadastrado');
      console.error('Erro ao cadastrar:', err.message);
      res.status(500).send('Erro ao cadastrar usuário');
    }
  } catch (err) {
    console.error('Erro na API:', err.message);
    res.status(500).send('Erro ao verificar o e-mail. Tente novamente.');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Não foi possível fazer logout.');
    res.redirect('/');
  });
});

app.get('/verify-2fa', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/');
  res.render('verify-2fa', { erro: null });
});

app.post('/verify-2fa', (req, res) => {
  const { code } = req.body;
  if (!req.session.verificationCode || Date.now() > req.session.verificationExpires) {
    return res.render('verify-2fa', { erro: 'Código expirado. Faça login novamente.' });
  }
  if (parseInt(code) !== req.session.verificationCode) {
    return res.render('verify-2fa', { erro: 'Código inválido.' });
  }
  req.session.email = req.session.pendingUser;
  delete req.session.pendingUser;
  delete req.session.verificationCode;
  delete req.session.verificationExpires;
  res.render('logado', { email: req.session.email });
});

app.get('/enable-2fa', (req, res) => {
  if (!req.session.email) return res.redirect('/');
  res.render('enable-2fa', { mensagem: null });
});

app.post('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');
  await db.execute('UPDATE users SET two_factor_enabled = true WHERE email = ?', [req.session.email]);
  res.render('enable-2fa', { mensagem: 'Autenticação de dois fatores ativada com sucesso.' });
});

app.listen(port, () => console.log(`Servidor rodando na porta ${port}`));
