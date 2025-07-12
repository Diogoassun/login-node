const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const db = require('./mysql'); // seu módulo de conexão MySQL
const nodemailer = require('nodemailer');

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

// Rota home/login
app.get('/', (req, res) => {
  if (req.session.email) {
    return res.render('logado', { email: req.session.email });
  }
  res.render('index', { erro: null, query: req.query || {} });
});

// Login POST
// Login POST (versão modificada para AJAX/JSON)
app.post('/', async (req, res) => {
  // O body agora virá como JSON do fetch
  const { email, password, 'g-recaptcha-response': captcha } = req.body;

  // Validação do reCAPTCHA
  if (!captcha) {
    return res.status(400).json({ success: false, message: 'Por favor, confirme que você não é um robô.' });
  }

  try {
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${recaptchaSecret}&response=${captcha}`;
    const response = await axios.post(verifyUrl);

    if (!response.data.success) {
      return res.status(400).json({ success: false, message: 'Falha na verificação do reCAPTCHA. Tente novamente.' });
    }

    // Validação do usuário
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ? AND password = ?', [email, password]);
    
    if (rows.length > 0) {
      const user = rows[0];

      // Se 2FA estiver ativado
      if (user.two_factor_enabled) {
        const codigo = Math.floor(100000 + Math.random() * 900000);
        req.session.pendingUser = user.email;
        req.session.verificationCode = codigo;
        req.session.verificationExpires = Date.now() + 5 * 60 * 1000; // 5 minutos

        await enviarEmail(user.email, 'Código de Verificação 2FA', `Seu código de verificação é: ${codigo}`);
        
        // Informa ao frontend para onde redirecionar
        return res.status(200).json({ success: true, redirectUrl: '/verify-2fa' });
      }

      // Login bem-sucedido sem 2FA
      req.session.email = user.email;
      // Informa ao frontend para onde redirecionar
      return res.status(200).json({ success: true, redirectUrl: '/logado' }); // Crie uma rota GET /logado se não existir
    } else {
      // Credenciais incorretas
      return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }
  } catch (err) {
    console.error('Erro no processo de login:', err.message);
    return res.status(500).json({ success: false, message: 'Erro interno no servidor. Tente mais tarde.' });
  }
});

// Adicione esta nova rota GET para a página de logado
app.get('/logado', (req, res) => {
  if (req.session.email) {
    return res.render('logado', { email: req.session.email });
  }
  res.redirect('/');
});

// Rota registro GET
app.get('/register', (req, res) => res.render('register'));

// Registro POST
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
    await db.execute('INSERT INTO users (email, password) VALUES (?, ?)', [email, password]);
    await enviarEmail(email, 'Bem-vindo!', 'Seu cadastro foi realizado com sucesso!');
    res.redirect('/?cadastro=sucesso');
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).send('Este e-mail já está cadastrado');
    console.error('Erro ao cadastrar:', err.message);
    res.status(500).send('Erro ao cadastrar usuário');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Não foi possível fazer logout.');
    res.redirect('/');
  });
});

// Página para digitar código 2FA
app.get('/verify-2fa', (req, res) => {
  if (!req.session.pendingUser) return res.redirect('/');
  res.render('verify-2fa', { erro: null });
});

// Verificar código 2FA
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

// Ativar 2FA simples (marcar no banco)
app.get('/enable-2fa', async (req, res) => {
  if (!req.session.email) return res.redirect('/');
  try {
    await db.execute('UPDATE users SET two_factor_enabled = 1 WHERE email = ?', [req.session.email]);
    res.render('enable-2fa', { mensagem: '2FA ativado com sucesso.' });
  } catch (err) {
    console.error('Erro ao ativar 2FA:', err);
    res.status(500).send('Erro ao ativar 2FA');
  }
});

app.listen(port, () => console.log(`Servidor rodando na porta ${port}`));


app.get('/forgot', (req, res) => {
  res.render('forgot', { erro: null, sucesso: null });
});

// Adicione o módulo 'crypto' no topo do seu index.js
const crypto = require('crypto');

// ... seu código existente ...

// ROTA PARA PROCESSAR O PEDIDO DE REDEFINIÇÃO DE SENHA
app.post('/forgot', async (req, res) => {
  const { email } = req.body;

  try {
    // 1. Encontra o usuário pelo e-mail
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

    // Medida de segurança: não informe se o e-mail foi encontrado ou não.
    // Apenas mostre uma mensagem genérica para evitar que descubram e-mails cadastrados.
    if (rows.length === 0) {
      return res.render('forgot', { 
        erro: null, 
        sucesso: 'Se este e-mail estiver cadastrado, um link de redefinição será enviado.' 
      });
    }
    const user = rows[0];

    // 2. Gera um token seguro e aleatório
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = Date.now() + 3600000; // Token expira em 1 hora

    // 3. Salva o token e a data de expiração no banco de dados
    // (Você precisará adicionar as colunas `reset_token` e `reset_token_expires` na sua tabela `users`)
    await db.execute(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
      [resetToken, resetTokenExpires, user.id]
    );

    // 4. Cria o link de redefinição e envia por e-mail
    const resetUrl = `http://localhost:${port}/reset/${resetToken}`;
    const mensagemEmail = `Você solicitou a redefinição de senha. Por favor, clique no link a seguir para criar uma nova senha: ${resetUrl}\n\nO link é válido por 1 hora.\n\nSe você não fez esta solicitação, ignore este e-mail.`;

    await enviarEmail(user.email, 'Redefinição de Senha', mensagemEmail);

    // 5. Renderiza a página com a mensagem de sucesso
    res.render('forgot', { 
      erro: null, 
      sucesso: 'Se este e-mail estiver cadastrado, um link de redefinição será enviado.' 
    });

  } catch (err) {
    console.error('Erro no processo /forgot:', err);
    res.render('forgot', { 
      sucesso: null, 
      erro: 'Ocorreu um erro interno. Por favor, tente novamente.' 
    });
  }
});

// ROTA PARA MOSTRAR O FORMULÁRIO DE NOVA SENHA
app.get('/reset/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const [rows] = await db.execute(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?',
      [token, Date.now()]
    );

    if (rows.length === 0) {
      return res.send('Token de redefinição inválido ou expirado.');
    }

    res.render('reset', { erro: null, token: token });

  } catch (err) {
    console.error('Erro no GET /reset/:token:', err);
    res.send('Ocorreu um erro.');
  }
});

// ROTA PARA SALVAR A NOVA SENHA
app.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render('reset', { erro: 'As senhas não coincidem.', token: token });
  }

  try {
    const [rows] = await db.execute(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?',
      [token, Date.now()]
    );

    if (rows.length === 0) {
      return res.render('reset', { erro: 'Token de redefinição inválido ou expirado.', token: token });
    }

    const user = rows[0];

    // Atualiza a senha e limpa os campos de token
    await db.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [password, user.id] // Lembre-se de usar HASH na senha em um projeto real!
    );

    res.send('Sua senha foi redefinida com sucesso! Você já pode <a href="/">fazer login</a>.');

  } catch (err) {
    console.error('Erro no POST /reset/:token:', err);
    res.render('reset', { erro: 'Ocorreu um erro ao redefinir a senha.', token: token });
  }
});