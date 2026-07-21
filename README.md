# Desafio_final-Criptografia
# Secure Chat — Projeto Final de Segurança da Informação

Aplicativo de mensagens em rede com **criptografia híbrida (RSA + AES)**,
**autenticação com hash de senha (PBKDF2-HMAC-SHA256)** e comunicação via
**sockets TCP** em Python.

## Estrutura

```
secure_chat/
├── server.py         # servidor de roteamento (autenticação + distribuição de chaves + roteamento)
├── client.py         # cliente de linha de comando
├── crypto_utils.py   # RSA-2048, AES-256-CBC, funções híbridas de encrypt/decrypt
├── auth.py           # cadastro/login com hash de senha (nunca texto claro)
├── database.py       # persistência simples em JSON (salt + hash)
├── requirements.txt
```

## Como executar

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

2. Em um terminal, inicie o servidor:
   ```bash
   python3 server.py
   ```

3. Em outros dois terminais (um para cada usuário), rode o cliente:
   ```bash
   python3 client.py
   ```
   (Se o servidor estiver em outra máquina: `python3 client.py <host> <porta>`.)

4. Em cada cliente, siga o fluxo:
   - `registrar` (na primeira vez) e depois `login` com usuário/senha.
   - Assim que os dois clientes estiverem logados, cada um recebe
     automaticamente a chave pública RSA do outro (`[*] Chave pública de 'X' recebida...`).
   - Para conversar:
     - `@usuario mensagem` — envia para um destinatário específico.
     - Só digitar a mensagem — envia automaticamente, se houver apenas 1 peer conectado.
     - `/peers` — lista os peers com chave já trocada.
     - `/quit` — encerra o cliente.

## Segurança: o que acontece "por baixo do capô"

1. **Cadastro/Login (`auth.py`)** — a senha nunca é armazenada. No cadastro,
   geramos um `salt` aleatório de 16 bytes e calculamos
   `PBKDF2-HMAC-SHA256(senha, salt, 100_000 iterações)`. Apenas `salt` e
   `hash` vão para `database.py`. No login, refazemos o mesmo cálculo com o
   salt salvo e comparamos os hashes em tempo constante (`hmac.compare_digest`),
   evitando timing attacks.

2. **Troca de chaves (`crypto_utils.py` + `server.py`)** — cada cliente gera
   seu próprio par RSA-2048 ao logar. Só a chave **pública** trafega e é
   redistribuída pelo servidor; a chave **privada** nunca sai da máquina do
   usuário.

3. **Mensagens (`crypto_utils.encrypt_message` / `decrypt_message`)** —
   para cada mensagem enviada:
   - gera-se uma chave AES-256 aleatória e um IV aleatório;
   - a mensagem é cifrada com AES-256-CBC (padding PKCS7);
   - a chave AES é cifrada com a chave pública RSA (OAEP) do destinatário;
   - o servidor recebe `{ciphertext, iv, encrypted_key}` e apenas
     **roteia** esse pacote — ele nunca tem acesso à chave privada, então
     nunca consegue ler o conteúdo.
   - o destinatário decifra a chave AES com sua chave privada e, com ela,
     decifra a mensagem.

4. **Comunicação (`net_utils.py` + `server.py`)** — os sockets TCP trocam
   mensagens JSON delimitadas por um cabeçalho de 4 bytes com o tamanho do
   payload, evitando problemas de fragmentação/concatenação típicos de TCP.

## Observações / limitações didáticas

- Este projeto ilustra os conceitos do Capítulo 3 (RSA, AES, hash, sockets).
  Ele **não** usa TLS no transporte; num sistema real de produção, a conexão
  TCP em si também deveria ser protegida (ex.: TLS) e senhas deveriam
  trafegar apenas sobre um canal já autenticado/cifrado.
- O servidor guarda usuários em um arquivo `users.json` (criado
  automaticamente na primeira execução) — suficiente para fins de
  demonstração, mas não é um banco de produção.
- Todas as primitivas criptográficas vêm da biblioteca `cryptography`
  (auditada); nenhum algoritmo foi implementado do zero, conforme pedido
  no enunciado.
