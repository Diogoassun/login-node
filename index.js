const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

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

  try {
    await db.execute('UPDATE users SET two_factor_enabled = 1 WHERE email = ?', [req.session.email]);
    res.render('enable-2fa', { mensagem: 'Autenticação de dois fatores ativada com sucesso.' });
  } catch (err) {
    console.error('Erro ao ativar 2FA:', err);
    res.status(500).send('Erro ao ativar autenticação de dois fatores.');
  }
});

app.get('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');

  try {
    // Gera secret para o usuário
    const secret = speakeasy.generateSecret({
      name: `SMAI (${req.session.email})`
    });

    // Salva secret temporariamente na sessão (ou no banco, para confirmar depois)
    req.session.twoFactorTempSecret = secret.base32;

    // Gera URL do QR code
    const otpauthUrl = secret.otpauth_url;

    // Gera QR code em base64 para mostrar na página
    const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);

    res.render('enable-2fa', { mensagem: null, qrCodeUrl });
  } catch (err) {
    console.error('Erro ao gerar QR code 2FA:', err);
    res.status(500).send('Erro ao gerar QR code para 2FA');
  }
});

// Rota POST para confirmar o código de 2FA inserido pelo usuário
app.post('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');
  const { token } = req.body;

  const tempSecret = req.session.twoFactorTempSecret;
  if (!tempSecret) return res.redirect('/enable-2fa');

  // Verifica o token com o secret temporário
  const verified = speakeasy.totp.verify({
    secret: tempSecret,
    encoding: 'base32',
    token: token,
    window: 1
  });

  if (verified) {
    // Salva no banco o secret definitivo e ativa 2FA
    try {
      await db.execute('UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE email = ?', [tempSecret, req.session.email]);

      // Remove secret temporário da sessão
      delete req.session.twoFactorTempSecret;

      res.render('enable-2fa', { mensagem: 'Autenticação de dois fatores ativada com sucesso.', qrCodeUrl: null });
    } catch (err) {
      console.error('Erro ao salvar 2FA no banco:', err);
      res.status(500).send('Erro ao salvar 2FA');
    }
  } else {
    // Token inválido, volta para a página mostrando o QR code para tentar de novo
    try {
      const otpauthUrl = speakeasy.otpauthURL({
        secret: tempSecret,
        label: `SMAI (${req.session.email})`,
        encoding: 'base32'
      });
      const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);

      res.render('enable-2fa', { mensagem: 'Código inválido. Tente novamente.', qrCodeUrl });
    } catch (err) {
      console.error('Erro ao gerar QR code:', err);
      res.status(500).send('Erro no servidor');
    }
  }
});

app.listen(port, () => console.log(`Servidor rodando na porta ${port}`));
