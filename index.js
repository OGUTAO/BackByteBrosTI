// Importações dos módulos necessários
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

// Inicialização do Express
const app = express();
const PORT = process.env.PORT || 8080;

// --- CONFIGURAÇÃO DO BANCO DE DADOS ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// --- MIDDLEWARES ESSENCIAIS ---

// **CORREÇÃO DE CORS APRIMORADA**
// Lista de origens permitidas
const allowedOrigins = [
  'https://sprightly-lollipop-a86be1.netlify.app',
  'http://localhost:8081',
  'http://127.0.0.1:5500'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Acesso não permitido por CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Métodos permitidos
  allowedHeaders: ['Content-Type', 'Authorization'], // Cabeçalhos permitidos
  optionsSuccessStatus: 200
};

// Habilita o pre-flight request para todas as rotas
app.options('*', cors(corsOptions));

// Usa o CORS com as opções definidas para todas as outras requisições
app.use(cors(corsOptions));

// Middleware para o Express entender requisições com corpo em JSON
app.use(express.json());


// --- ROTAS ---

// Rota raiz para verificar se a API está online
app.get('/', (req, res) => {
  res.send('API da ByteBros.TI no ar! Tudo funcionando.');
});


// --- ROTAS DE AUTENTICAÇÃO ---

// Rota para REGISTRAR um novo usuário
app.post('/api/auth/registrar', async (req, res) => {
  const { nome_completo, email, telefone, senha } = req.body;
  if (!nome_completo || !email || !senha) {
    return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nome_completo, email, telefone, senha) VALUES ($1, $2, $3, $4) RETURNING id, email, nome_completo',
      [nome_completo, email.toLowerCase(), telefone, hashedPassword]
    );
    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET || 'seu_segredo_jwt', { expiresIn: '1d' });
    res.status(201).json({ token, nome: user.nome_completo, email: user.email });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ erro: 'Erro ao registrar usuário. O e-mail já pode estar em uso.' });
  }
});

// Rota para LOGIN (serve para usuários e administradores)
app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email.toLowerCase()]);
        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'Credenciais inválidas.' });
        }
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(senha, user.senha);
        if (!isMatch) {
            return res.status(401).json({ erro: 'Credenciais inválidas.' });
        }
        const token = jwt.sign({ userId: user.id, email: user.email, isAdmin: user.is_admin }, process.env.JWT_SECRET || 'seu_segredo_jwt', { expiresIn: '1d' });
        res.json({ token, nome: user.nome_completo, email: user.email, is_admin: user.is_admin });
    } catch (error) {
        res.status(500).json({ erro: 'Erro no servidor durante o login.' });
    }
});


// --- ROTAS PÚBLICAS (NÃO PRECISAM DE LOGIN) ---

app.get('/api/produtos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM produtos ORDER BY criado_em DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao buscar produtos.' });
    }
});

app.get('/api/noticias', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM noticias ORDER BY data DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao buscar notícias.' });
    }
});

app.post('/api/suporte', async (req, res) => {
    const { nome, email, telefone, mensagem, tipo_interacao, servico_nome } = req.body;
    try {
        await pool.query(
            'INSERT INTO interacoes (nome, email, telefone, mensagem, tipo_interacao, servico_nome) VALUES ($1, $2, $3, $4, $5, $6)',
            [nome, email, telefone, mensagem, tipo_interacao, servico_nome]
        );
        res.status(201).json({ message: 'Mensagem recebida com sucesso!' });
    } catch (error) {
        console.error('Erro ao salvar interação:', error);
        res.status(500).json({ erro: 'Erro ao salvar mensagem.' });
    }
});


// --- ROTAS PROTEGIDAS (PRECISAM DE LOGIN) ---
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET || 'seu_segredo_jwt', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/api/pedidos', authMiddleware, async (req, res) => {
    const { itens, endereco_entrega, valor_frete, valor_total, forma_pagamento, prazo_entrega } = req.body;
    const cliente_email = req.user.email;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const pedidoResult = await client.query(
            'INSERT INTO pedidos (cliente_email, endereco_entrega, valor_frete, valor_total, forma_pagamento, prazo_entrega) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [cliente_email, endereco_entrega, valor_frete, valor_total, forma_pagamento, prazo_entrega]
        );
        const pedidoId = pedidoResult.rows[0].id;
        for (const item of itens) {
            await client.query(
                'INSERT INTO pedido_itens (pedido_id, produto_id, nome_produto, quantidade, valor_unitario) VALUES ($1, $2, $3, $4, $5)',
                [pedidoId, item.produto_id, item.nome_produto, item.quantidade, item.valor_unitario]
            );
        }
        await client.query('COMMIT');
        res.status(201).json({ message: 'Pedido criado com sucesso!', pedidoId });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erro ao criar pedido:', error);
        res.status(500).json({ erro: 'Erro ao criar pedido.' });
    } finally {
        client.release();
    }
});

app.get('/api/meus-pedidos', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM pedidos WHERE cliente_email = $1 ORDER BY data_pedido DESC', [req.user.email]);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao buscar pedidos.' });
    }
});


// --- INICIALIZAÇÃO DO SERVIDOR ---
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
