const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql'); // conexão com MySQL
const nodemailer = require('nodemailer');
const crypto = require('crypto');

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
    return res.render('logado', { email: rows[0].email });
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
  const user = rows[0];

  if (user.two_factor_enabled) {
    // Gera código de verificação e salva em sessão
    const verificationCode = Math.floor(100000 + Math.random() * 900000); // 6 dígitos
    req.session.pendingUser = user.email;
    req.session.verificationCode = verificationCode;
    req.session.verificationExpires = Date.now() + 5 * 60 * 1000; // 5 minutos

    await enviarEmail(user.email, 'Código de Verificação 2FA', `Seu código de verificação é: ${verificationCode}`);

    return res.redirect('/verify-2fa');
  }

  req.session.email = user.email;
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
        await enviarEmail(email, 'Bem-vindo!', 'Seu cadastro foi realizado com sucesso!', 'desfrute do que o nosso sistema de monitoramento inteligente tem para lhe oferecer!');

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

// --------------- Rota para página "Esqueci minha senha"
app.get('/forgot', (req, res) => {
  res.render('forgot', { erro: null, sucesso: null });
});

// --------------- Enviar e-mail com link para resetar senha
app.post('/forgot', async (req, res) => {
  const { email } = req.body;

  // Verifica se e-mail existe
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.render('forgot', { erro: 'E-mail não cadastrado.', sucesso: null });
    }

    // Gera token aleatório
    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // válido por 1 hora

    // Salva token no banco
    await db.execute(
      'INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)',
      [email, token, expiresAt]
    );

    // Monta link de redefinição
    const resetLink = `${req.protocol}://${req.get('host')}/reset/${token}`;

    // Envia email com o link
    const mensagem = `Você solicitou redefinição de senha.\nClique no link para alterar sua senha:\n${resetLink}\n\nEste link é válido por 1 hora.`;

    await enviarEmail(email, 'Redefinição de senha', mensagem);

    res.render('forgot', { erro: null, sucesso: 'Email enviado com instruções para redefinir a senha.' });

  } catch (err) {
    console.error(err);
    res.status(500).send('Erro no servidor');
  }
});

// --------------- Página para resetar senha (formulário)
app.get('/reset/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const [rows] = await db.execute(
      'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()',
      [token]
    );

    if (rows.length === 0) {
      return res.send('Token inválido ou expirado.');
    }

    res.render('reset', { token, erro: null });
  } catch (err) {
    console.error(err);
    res.status(500).send('Erro no servidor');
  }
});

// --------------- Recebe nova senha e atualiza no banco
app.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password) return res.render('reset', { token, erro: 'Digite a nova senha.' });

  try {
    // Verifica token válido
    const [rows] = await db.execute(
      'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()',
      [token]
    );

    if (rows.length === 0) {
      return res.send('Token inválido ou expirado.');
    }

    const email = rows[0].email;

    // Atualiza senha (atenção: ideal criptografar a senha antes)
    await db.execute('UPDATE users SET password = ? WHERE email = ?', [password, email]);

    // Remove token (opcional, para segurança)
    await db.execute('DELETE FROM password_reset_tokens WHERE token = ?', [token]);

    res.send('Senha atualizada com sucesso! Agora você pode fazer login.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Erro no servidor');
  }
});

app.get('/verify-2fa', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/');
  res.render('verify-2fa', { erro: null });
});

app.post('/verify-2fa', async (req, res) => {
  const { code } = req.body;

  if (!req.session.verificationCode || Date.now() > req.session.verificationExpires) {
    return res.render('verify-2fa', { erro: 'Código expirado. Faça login novamente.' });
  }

  if (parseInt(code) !== req.session.verificationCode) {
    return res.render('verify-2fa', { erro: 'Código inválido.' });
  }

  // Código válido
  req.session.email = req.session.pendingUser;
  delete req.session.pendingUser;
  delete req.session.verificationCode;
  delete req.session.verificationExpires;

  res.render('logado');
});


app.get('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');
  res.render('enable-2fa', { mensagem: null });
});

app.post('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');

  await db.execute('UPDATE users SET two_factor_enabled = true WHERE email = ?', [req.session.email]);
  res.render('enable-2fa', { mensagem: 'Autenticação de dois fatores ativada com sucesso.' });
});
