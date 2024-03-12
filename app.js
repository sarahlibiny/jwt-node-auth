require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

//config json response
app.use(express.json()); //comeca a aceitar json

// Models
const User = require("./models/User");

//Open Route - public route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa API" });
});

//private route
//vai dar informacoes do usuario pelo id
//o id vem pela url
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  //consultar no banco se o user existe
  const user = await User.findById(id, "-password");
  //exclui a senha do campo p n ficar visivel

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado" });
  }

  res.status(200).json({ user });
});

//funcao que verifica o token p rota privada
//parametro next eh quando da certo a requisicao e continua
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  //split divide onde tem espaco e pegamos a segunda parte

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado" });
  }

  //verificar token
  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ msg: "Token inválido" });
  }
}

//registrar usuario
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  if (!name) {
    return res.status(422).json({ msg: "Nome é obrigatório" });
  }
  if (!email) {
    return res.status(422).json({ msg: "Email é obrigatório" });
  }
  if (!password) {
    return res.status(422).json({ msg: "Senha é obrigatório" });
  }
  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "As senhas não conferem" });
  }

  //check se o user existe
  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(422).json({ msg: "Por favor, utilize outro e-mail" });
  }

  //criando password
  const salt = await bcrypt.genSalt(12); //adiciona 12 caracteres a mais do q do usuario
  const passwordHash = await bcrypt.hash(password, salt); //cria um hash passando a senha e o salt criado

  //criando o usuario
  //faz uma instancia do model user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save(); //persiste no banco de dados
    res.status(201).json({ msg: "Usuário criado com sucesso" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "Ocorreu erro no servidor" }); //n eh a melhor alternativa correto salvar em log
  }
});

//Login User
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //validacoes
  if (!email) {
    return res.status(422).json({ msg: "Email é obrigatório" });
  }
  if (!password) {
    return res.status(422).json({ msg: "Senha é obrigatório" });
  }

  //check se o user existe
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado" }); //erro 404 not found
  }

  //verificando senha se combina com o banco
  const checkPassword = await bcrypt.compare(password, user.password);
  //posso acessar a prop password e verificar com a senha q usuario enviou

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha incorreta" });
  }

  //logar o usuario autenticacao no sistema
  try {
    const secret = process.env.SECRET;
    //o token vai com o id do usuario e a variavel secret q foi criada
    //no front salva no local storage pega na requisicao e envia pelos headers

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autenticação realizada com sucesso", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      msg: "Ocorreu erro no servidor",
    });
  }
});

//credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

//primeiro conectar a api antes de acessar ela
mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.hl9uynn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
  )
  .then(() => {
    app.listen(3000);
    console.log("Conexão ao banco de dados feita com sucesso");
  })
  .catch((err) => console.log(err));
