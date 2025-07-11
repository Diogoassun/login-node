const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql'); // conexão com MySQL
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 3000;

// --- CONFIGURAÇÃO DO NODEMAILER ---
// Usando as suas credenciais do Gmail com a senha de app
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'bandeiradiogo96@gmail.com', // Seu e-mail
    pass: 'hwbkedimtmwblxmv'           // Sua senha de app (sem espaços)
  }
});

// --- FUNÇÃO PARA ENVIAR E-MAIL ---
async function enviarEmail(destinatario, assunto, mensagemHtml) {
  try {
    const info = await transporter.sendMail({
      from: '"Meu Sistema de Login" <bandeiradiogo96@gmail.com>', // Remetente
      to: destinatario, // E-mail do usuário que se cadastrou
      subject: assunto,  // Assunto do e-mail
      html: mensagemHtml // Conteúdo do e-mail em HTML
    });
    console.log('E-mail enviado: %s', info.messageId);
  } catch (erro) {
    console.error('Erro ao enviar e-mail:', erro.message);
  }
}
// ------------------------------------

// Suas chaves de API
const mailboxApiKey = 'e37b7fc9c000be253433294d102f9622'; // Mailboxlayer
const recaptchaSecret = '6Leu9H4rAAAAAHlL0O_fcrJe4i1AgaXW_tPjduUs'; // reCAPTCHA (SECRET KEY)

// Configuração da Sessão
app.use(session({
  secret: 'mysecretkey', // Em produção, use uma chave mais segura
  resave: false,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: true }));

// Configuração das Views (EJS) e arquivos estáticos (CSS)
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));

// Rota da página inicial
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

// Rota de Login
app.post('/', async (req, res) => {
  const { email, password, 'g-recaptcha-response': captcha } = req.body;

  if (!captcha) {
    return res.render('index', { erro: 'Por favor, confirme que você não é um robô.', query: {} });
  }

  try {
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${recaptchaSecret}&response=${captcha}`;
    const response = await axios.post(verifyUrl);

    if (!response.data.success) {
      return res.render('index', { erro: 'Falha na verificação do reCAPTCHA.', query: {} });
    }

    const [rows] = await db.execute('SELECT * FROM users WHERE email = ? AND password = ?', [email, password]);

    if (rows.length > 0) {
      req.session.email = rows[0].email;
      return res.render('logado');
    } else {
      return res.render('index', { erro: 'E-mail ou senha incorretos', query: {} });
    }
  } catch (err) {
    console.error('Erro no processo de login:', err.message);
    return res.status(500).send('Erro interno no servidor.');
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
      params: { access_key: mailboxApiKey, email: email, smtp: 1, format: 1 }
    });

    if (!response.data.format_valid || !response.data.mx_found || response.data.disposable) {
      return res.status(400).send('Este endereço de e-mail não é válido ou não é permitido.');
    }

    await db.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, password]);

    // Envia e-mail de boas-vindas usando a função
    const mensagemBoasVindas = `
      <h1>Olá, ${email}!</h1>
      <p>Seu cadastro em nosso sistema foi realizado com sucesso.</p>
      <p>Agradecemos por se juntar a nós.</p>
      <p>Atenciosamente,<br>Equipe do Sistema</p>
    `;
    await enviarEmail(email, 'Bem-vindo(a) ao Sistema!', mensagemBoasVindas);

    res.redirect('/?cadastro=sucesso');

  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).send('Este e-mail já está cadastrado');
    }
    console.error('Erro no processo de cadastro:', err.message);
    res.status(500).send('Erro ao realizar o cadastro. Tente novamente.');
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
