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
// Conecta ao banco de dados Neon usando a URL do ambiente
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// --- MIDDLEWARES ESSENCIAIS ---

// Configuração do CORS para permitir acesso do seu site e de ambiente local
const allowedOrigins = [
  'https://sprightly-lollipop-a86be1.netlify.app', // Seu site no Netlify
  'http://localhost:8081', // Exemplo para desenvolvimento local
  'http://127.0.0.1:5500' // Exemplo para Live Server do VS Code
];

const corsOptions = {
  origin: function (origin, callback) {
    // Permite requisições sem 'origin' (como apps mobile ou Postman) ou se a origem estiver na lista
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
};
app.use(cors(corsOptions));

// Middleware para o Express entender requisições com corpo em JSON
// ESTA ERA A LINHA FALTANTE E CRUCIAL
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
    // Criptografa a senha antes de salvar
    const hashedPassword = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nome_completo, email, telefone, senha) VALUES ($1, $2, $3, $4) RETURNING id, email, nome_completo',
      [nome_completo, email.toLowerCase(), telefone, hashedPassword]
    );
    const user = result.rows[0];
    
    // Gera um token de login para o novo usuário
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

        // Compara a senha enviada com a senha criptografada no banco
        const isMatch = await bcrypt.compare(senha, user.senha);
        if (!isMatch) {
            return res.status(401).json({ erro: 'Credenciais inválidas.' });
        }

        // Gera o token de login
        const token = jwt.sign({ userId: user.id, email: user.email, isAdmin: user.is_admin }, process.env.JWT_SECRET || 'seu_segredo_jwt', { expiresIn: '1d' });
        
        res.json({ token, nome: user.nome_completo, email: user.email, is_admin: user.is_admin });
    } catch (error) {
        res.status(500).json({ erro: 'Erro no servidor durante o login.' });
    }
});


// --- ROTAS PÚBLICAS (NÃO PRECISAM DE LOGIN) ---

// Rota para listar todos os produtos da loja
app.get('/api/produtos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM produtos ORDER BY criado_em DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao buscar produtos.' });
    }
});

// Rota para listar todas as notícias
app.get('/api/noticias', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM noticias ORDER BY data DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ erro: 'Erro ao buscar notícias.' });
    }
});

// Rota para formulários de Suporte e Orçamento
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

// Middleware para verificar se o token de login é válido
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"
    if (!token) return res.sendStatus(401); // Não autorizado

    jwt.verify(token, process.env.JWT_SECRET || 'seu_segredo_jwt', (err, user) => {
        if (err) return res.sendStatus(403); // Proibido (token inválido)
        req.user = user; // Adiciona os dados do usuário (email, id) na requisição
        next();
    });
};

// Rota para criar um novo pedido na loja
app.post('/api/pedidos', authMiddleware, async (req, res) => {
    const { itens, endereco_entrega, valor_frete, valor_total, forma_pagamento, prazo_entrega } = req.body;
    const cliente_email = req.user.email; // Pega o email do usuário logado (do token)

    const client = await pool.connect(); // Pega uma conexão para fazer uma transação
    try {
        await client.query('BEGIN'); // Inicia a transação

        // 1. Insere o pedido principal na tabela 'pedidos'
        const pedidoResult = await client.query(
            'INSERT INTO pedidos (cliente_email, endereco_entrega, valor_frete, valor_total, forma_pagamento, prazo_entrega) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [cliente_email, endereco_entrega, valor_frete, valor_total, forma_pagamento, prazo_entrega]
        );
        const pedidoId = pedidoResult.rows[0].id;

        // 2. Insere cada item do carrinho na tabela 'pedido_itens'
        for (const item of itens) {
            await client.query(
                'INSERT INTO pedido_itens (pedido_id, produto_id, nome_produto, quantidade, valor_unitario) VALUES ($1, $2, $3, $4, $5)',
                [pedidoId, item.produto_id, item.nome_produto, item.quantidade, item.valor_unitario]
            );
        }

        await client.query('COMMIT'); // Confirma a transação se tudo deu certo
        res.status(201).json({ message: 'Pedido criado com sucesso!', pedidoId });
    } catch (error) {
        await client.query('ROLLBACK'); // Desfaz tudo se deu algum erro
        console.error('Erro ao criar pedido:', error);
        res.status(500).json({ erro: 'Erro ao criar pedido.' });
    } finally {
        client.release(); // Libera a conexão de volta para o pool
    }
});

// Rota para listar os pedidos do usuário que está logado
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
