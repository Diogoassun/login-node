// index.js

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql'); // Este arquivo ainda lida com a conexão do DB
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// --- BLOCO DE CONFIGURAÇÃO (NÃO RECOMENDADO PARA PRODUÇÃO) ---
// Substitua todos os valores abaixo pelos seus.
const CONFIG = {
  PORT: 3000,
  GMAIL_USER: 'bandeiradiogo96@gmail.com',
  GMAIL_PASS: 'hwbk edim tmwb lxmv', // Lembre-se: use uma Senha de App do Google
  MAILBOX_API_KEY: 'e37b7fc9c000be253433294d102f9622',
  RECAPTCHA_SECRET: '6Leu9H4rAAAAAHlL0O_fcrJe4i1AgaXW_tPjduUs',
  SESSION_SECRET: 'mysecretkey_super_secreta_e_dificil',
  // Gere suas próprias chaves! Não use estas.
  CRYPTO_SECRET_KEY: 'c8b7a695e4d3c2b1a09876543210fedcba9876543210fedcba9876543210feab',
  CRYPTO_IV: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'
};
// -------------------------------------------------------------

const app = express();
const port = CONFIG.PORT || 3000;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: CONFIG.GMAIL_USER,
    pass: CONFIG.GMAIL_PASS
  }
});

// Configuração e Funções de Criptografia
const ALGORITHM = 'aes-256-cbc';
const SECRET_KEY = Buffer.from(CONFIG.CRYPTO_SECRET_KEY, 'hex');
const IV = Buffer.from(CONFIG.CRYPTO_IV, 'hex');

function encrypt(text) {
  const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, IV);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(hash) {
  const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, IV);
  let decrypted = decipher.update(hash, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Função de envio de e-mail
async function enviarEmail(destinatario, assunto, mensagem) {
  try {
    const info = await transporter.sendMail({
      from: `"SMAI" <${CONFIG.GMAIL_USER}>`,
      to: destinatario,
      subject: assunto,
      text: mensagem
    });
    console.log('E-mail enviado: %s', info.messageId);
  } catch (erro) {
    console.error('Erro ao enviar e-mail:', erro.message);
  }
}

app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));


// Rota home/login
app.get('/', (req, res) => {
  if (req.session.email) {
    return res.render('logado', { email: req.session.email });
  }
  res.render('index', { erro: null, query: req.query || {} });
});


// Rota de Login com Criptografia
app.post('/', async (req, res) => {
  const { email, password, 'g-recaptcha-response': captcha } = req.body;
  if (!captcha) return res.render('index', { erro: 'Por favor, confirme que você não é um robô.', query: {} });

  try {
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${CONFIG.RECAPTCHA_SECRET}&response=${captcha}`;
    const response = await axios.post(verifyUrl);
    if (!response.data.success) return res.render('index', { erro: 'Falha na verificação do reCAPTCHA.', query: {} });

    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const [rows] = await db.execute('SELECT * FROM users WHERE email_hash = ?', [emailHash]);

    if (rows.length > 0) {
      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        const decryptedEmail = decrypt(user.email);
        if (user.two_factor_enabled) {
          const codigo = Math.floor(100000 + Math.random() * 900000);
          req.session.pendingUser = decryptedEmail;
          req.session.verificationCode = codigo;
          req.session.verificationExpires = Date.now() + 5 * 60 * 1000;
          await enviarEmail(decryptedEmail, 'Código de Verificação 2FA', `Seu código de verificação é: ${codigo}`);
          return res.redirect('/verify-2fa');
        }
        req.session.email = decryptedEmail;
        return res.render('logado', { email: decryptedEmail });
      }
    }
    return res.render('index', { erro: 'E-mail ou senha incorretos', query: {} });

  } catch (err) {
    console.error('Erro no login:', err.message);
    return res.status(500).send('Erro no servidor durante o login.');
  }
});


// Rota registro GET
app.get('/register', (req, res) => res.render('register'));


// Rota de Registro com Criptografia
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Preencha o e-mail e a senha');
  
  const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailValido) return res.status(400).send('Formato de e-mail inválido');

  try {
    const response = await axios.get('http://apilayer.net/api/check', {
      params: { access_key: CONFIG.MAILBOX_API_KEY, email, smtp: 1, format: 1 }
    });
    if (!response.data.format_valid || !response.data.mx_found || response.data.disposable) {
      return res.status(400).send('Este endereço de e-mail não é válido ou não é permitido.');
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const encryptedEmail = encrypt(email);
    const emailHash = crypto.createHash('sha256').update(email).digest('hex');

    await db.execute(
      'INSERT INTO users (email, password, email_hash) VALUES (?, ?, ?)',
      [encryptedEmail, hashedPassword, emailHash]
    );

    await enviarEmail(email, 'Bem-vindo!', 'Seu cadastro foi realizado com sucesso!');
    res.redirect('/?cadastro=sucesso');
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).send('Este e-mail já está cadastrado');
    }
    console.error('Erro ao cadastrar:', err.message);
    res.status(500).send('Erro ao cadastrar usuário');
  }
});


// Rota de Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Não foi possível fazer logout.');
    res.redirect('/');
  });
});


// Rotas de 2FA
app.get('/verify-2fa', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/');
  res.render('verify-2fa', { erro: null });
});

app.post('/verify-2fa', (req, res) => {
  const { code } = req.body;
  if (!req.session.verificationCode || Date.now() > req.session.verificationExpires) {
    return res.render('verify-2fa', { erro: 'Código expirado. Faça login novamente.' });
  }
  if (parseInt(code) === req.session.verificationCode) {
    req.session.email = req.session.pendingUser;
    delete req.session.pendingUser;
    delete req.session.verificationCode;
    delete req.session.verificationExpires;
    return res.render('logado', { email: req.session.email });
  } else {
    return res.render('verify-2fa', { erro: 'Código incorreto. Tente novamente.' });
  }
});


// Rota para ativar 2FA
app.get('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');
  try {
    const emailHash = crypto.createHash('sha256').update(req.session.email).digest('hex');
    await db.execute('UPDATE users SET two_factor_enabled = 1 WHERE email_hash = ?', [emailHash]);
    res.render('enable-2fa', { mensagem: '2FA ativado com sucesso.' });
  } catch (err) {
    console.error('Erro ao ativar 2FA:', err);
    res.status(500).send('Erro ao ativar 2FA');
  }
});

app.listen(port, () => console.log(`Servidor rodando na porta ${port}`));