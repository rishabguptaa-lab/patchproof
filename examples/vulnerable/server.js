import express from 'express';
import { exec } from 'node:child_process';
const app = express();
const apiKey = "demo_secret_abcdefghijklmnop";
app.get('/download', (req, res) => res.sendFile(req.query.file));
app.get('/tools', (req, res) => exec(`git show ${req.query.ref}`, (_, out) => res.send(out)));
app.get('/next', (req, res) => res.redirect(req.query.url));
app.listen(3000);
