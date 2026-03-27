const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 5000;

// Stockage temporaire
const passwordStore = {};

// ---------- Fonctions ----------
function generatePassword(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`';
  let pwd = '';
  for (let i = 0; i < length; i++) {
    pwd += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return pwd;
}

function encryptPassword(pwd) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(pwd, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return { encrypted, key: key.toString('base64'), iv: iv.toString('base64') };
}

function decryptPassword(encrypted, keyBase64, ivBase64) {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = Buffer.from(ivBase64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ---------- ROUTES ----------

// 🟢 PAGE 1 : Accueil
app.get('/', (req, res) => {
  res.send(`
    <html>
    <body>
      <h2>Bienvenue sur cette plateforme de sécurisation du transfert des secrets</h2>

      <p><strong>Développée et déployée par RAKOTONIRINA Daniella Nandrianina Natacha</strong><br>
      Stagiaire au sein du département Sécurité SI chez Orange Madagascar</p>

      <p>
      -Technologie utilisée : Node.js v24.11.1<br>
      -Méthode de chiffrement : AES-256-CBC (crypto)<br>
      -UUID pour chaque lien sécurisé<br>
      -Déployée sur Render
      </p>

      <h3>Fonctionnement :</h3>
      <ul>
        <li>L'admin crée ou insère un mot de passe</li>
        <li>Le mot de passe est chiffré avant stockage dans une variable temporaire</li>
        <li>Un UUID est généré pour créer un lien unique encore en local et http</li>
        <li>Le lien expire après clic ou 1h</li>
        <li>Mot de passe affiché masqué mais copiable</li>
        <li>Usage unique puis suppression de la variable temporaire</li>
      </ul>

      <h3>Remarque :</h3>
      <ul>
        <li>Cette version n'a pas encore de base de données</li>
        <li>Une page d'authentification des admins(limités au nombre de 2) sera mise en place</li>
      </ul>

      <p><i>Mes compétences en front-end sont en vacances haha!</i></p>

      <a href="/setup">
        <button>Commencer la simulation</button>
      </a>
    </body>
    </html>
  `);
});

// 🟡 PAGE 2 : Formulaire
app.get('/setup', (req, res) => {
  res.send(`
    <html>
    <body>
      <h2>Informations de la simulation</h2>
      <form action="/home" method="get">
        <input type="text" name="admin" placeholder="Admin (trigramme)" required><br><br>
        <input type="text" name="service" placeholder="Service" required><br><br>
        <input type="text" name="user" placeholder="Utilisateur (trigramme)" required><br><br>
        <button type="submit">Continuer</button>
      </form>
    </body>
    </html>
  `);
});

// 🔵 PAGE 3 : Menu principal
app.get('/home', (req, res) => {
  const { admin, service, user } = req.query;

  res.send(`
    <html>
    <body>
      <h2>Création du lien sécurisé</h2>

      <p><strong>Admin:</strong> ${admin} | 
      <strong>Service:</strong> ${service} | 
      <strong>Utilisateur:</strong> ${user}</p>

      <p><a href="/generate?admin=${admin}&service=${service}&user=${user}">Générer un nouveau mot de passe</a></p>

      <p>Ou sécuriser un mot de passe existant :</p>
      <form action="/send" method="get">
        <input type="hidden" name="admin" value="${admin}">
        <input type="hidden" name="service" value="${service}">
        <input type="hidden" name="user" value="${user}">
        <input type="text" name="pwd" placeholder="Mot de passe existant" required>
        <button type="submit">Envoyer en lien sécurisé</button>
      </form>

      <p>Les mots de passe expirent après 1h.</p>
    </body>
    </html>
  `);
});

// Génération
app.get('/generate', (req, res) => {
  const { admin, service, user } = req.query;

  const pwd = generatePassword();
  const { encrypted, key, iv } = encryptPassword(pwd);
  const id = uuidv4();

  passwordStore[id] = {
    encrypted,
    key,
    iv,
    timestamp: Date.now(),
    ttl: 3600000,
    admin,
    service,
    user
  };

  res.send(`
    Lien sécurisé : 
    <a href="/access/${id}">http://localhost:${port}/access/${id}</a>
  `);
});

// Envoi
app.get('/send', (req, res) => {
  const { pwd, admin, service, user } = req.query;
  if (!pwd) return res.send('Erreur : mot de passe manquant.');

  const { encrypted, key, iv } = encryptPassword(pwd);
  const id = uuidv4();

  passwordStore[id] = {
    encrypted,
    key,
    iv,
    timestamp: Date.now(),
    ttl: 3600000,
    admin,
    service,
    user
  };

  res.send(`
    Lien sécurisé : 
    <a href="/access/${id}">http://localhost:${port}/access/${id}</a>
  `);
});

// Accès
app.get('/access/:id', (req, res) => {
  const data = passwordStore[req.params.id];
  if (!data) return res.send('Lien invalide ou expiré.');

  if (Date.now() - data.timestamp > data.ttl) {
    delete passwordStore[req.params.id];
    return res.send('Lien expiré.');
  }

  const pwd = decryptPassword(data.encrypted, data.key, data.iv);
  delete passwordStore[req.params.id];

  res.send(`
    <html>
    <body>
      <p>Mot de passe :
        <input type="password" value="${pwd}" id="pwd" readonly>
        <button onclick="navigator.clipboard.writeText(document.getElementById('pwd').value)">Copier</button>
      </p>
    </body>
    </html>
  `);
});

// Serveur
app.listen(port, '0.0.0.0', () => {
  console.log(`Serveur démarré sur http://localhost:${port}`);
});