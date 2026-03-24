// server.js
// Importation des modules
const express = require('express'); //framework web pour créer le serveur et les routes HTTP
const crypto = require('crypto'); //bibliothèque native Node.js pour chiffrer/déchiffrer les mots de passe
const { v4: uuidv4 } = require('uuid'); //générer des identifiants uniques (UUID) pour chaque lien sécurisé

//Initialisation serveur
const app = express(); //instance de l'application Express
const port = 5000; //Port d'écoute du serveur

// Stockage temporaire des mots de passe chiffrés, la clé, l’IV, l’UUID et la date
const passwordStore = {};

// ---------- Fonctions ----------
//Génération de mot de passe aléatoire à 12 caractères à partir des chars proposés
function generatePassword(length = 12) { // longueur limitée à 12 caractères
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`';
  let pwd = '';
  for (let i = 0; i < length; i++) {
    pwd += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return pwd;
}

//Chiffre le mot de passe avec AES-256-CBC : key et iv sont générés aléatoirement
//Retourne : encrypted → mot de passe chiffré + key et iv → nécessaires pour déchiffrer plus tard
function encryptPassword(pwd) {
  const key = crypto.randomBytes(32); // AES-256
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(pwd, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return { encrypted, key: key.toString('base64'), iv: iv.toString('base64') };
}

//Déchiffre un mot de passe à partir de l’encrypted, la key et l’iv
//Retourne le mot de passe en clair
function decryptPassword(encrypted, keyBase64, ivBase64) {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = Buffer.from(ivBase64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ---------- Routes ----------
// Page d'accueil
//Options pour générer un mot de passe et pour sécuriser un mot de passe existant via formulaire
app.get('/', (req, res) => {
  res.send(`
    <html>
    <body>
      <h2>Serveur de mot de passe sécurisé</h2>
      <p><a href="/generate">Générer un nouveau mot de passe</a></p>
      <p>Ou sécuriser un mot de passe existant :</p>
      <form action="/send" method="get">
        <input type="text" name="pwd" placeholder="Mot de passe existant" required>
        <button type="submit">Envoyer en lien sécurisé</button>
      </form>
      <p>Les mots de passe sont à usage unique et expirent après 1h.</p>
    </body>
    </html>
  `);
});

// Générer nouveau mot de passe
//Crée un mot de passe aléatoire - Chiffre le mot de passe -Stocke dans passwordStore avec UUID, timestamp et TTL 1h -Génère le lien sécurisé
app.get('/generate', (req, res) => {
  const pwd = generatePassword(); // 12 caractères
  const { encrypted, key, iv } = encryptPassword(pwd);
  const id = uuidv4();
  passwordStore[id] = { encrypted, key, iv, timestamp: Date.now(), ttl: 3600000 };
  res.send(`Nouveau mot de passe généré ! Lien sécurisé : <a href="/access/${id}">http://localhost:${port}/access/${id}</a>`);
});

// Sécuriser mot de passe existant
//Même logique que /generate mais pour un mot de passe fourni par l’utilisateur
app.get('/send', (req, res) => {
  const { pwd } = req.query;
  if (!pwd) return res.send('Erreur : mot de passe manquant.');
  const { encrypted, key, iv } = encryptPassword(pwd);
  const id = uuidv4();
  passwordStore[id] = { encrypted, key, iv, timestamp: Date.now(), ttl: 3600000 };
  res.send(`Lien sécurisé généré : <a href="/access/${id}">http://localhost:${port}/access/${id}</a>`);
});

// Accéder au mot de passe via UUID
//Vérifie si l’UUID existe et si le TTL n’est pas dépassé - Déchiffre le mot de passe - Supprime l’entrée pour usage unique - Affiche le mot de passe masqué + bouton “Copier”
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
      <p>Copiez-le dans KeePass et fermez cette page.</p>
    </body>
    </html>
  `);
});



// Lancer serveur
app.listen(port, '0.0.0.0', () => console.log(`Serveur Node.js démarré sur http://localhost:${port}`));