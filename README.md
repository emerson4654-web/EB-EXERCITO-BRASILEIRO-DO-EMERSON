# EB Manager — Emerson (login e verificação real da bio Roblox)

Esta versão deixa `index.html`, `server.js` e `package.json` todos na raiz, sem a pasta `public`.

## Publicar pelo GitHub e Render
1. Crie um repositório no GitHub.
2. Envie os quatro arquivos que estão na raiz deste projeto: `index.html`, `server.js`, `package.json` e `README.md`.
3. No Render, selecione **New + → Web Service** e conecte o repositório.
4. Configure:
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
5. Em **Environment**, crie `SESSION_SECRET` com uma sequência aleatória de pelo menos 32 caracteres. Não use nem compartilhe sua chave de API do Roblox como segredo de sessão.
6. Publique e abra a URL gerada pelo Render.
7. Confira se `https://SUA-URL.onrender.com/api/health` retorna JSON com `"ok":true`.

## Como funciona
- `POST /api/auth/start`: procura o nome de usuário pelo endpoint público do Roblox e gera um código com validade de 10 minutos.
- `POST /api/auth/verify`: consulta a descrição pública do perfil e só autentica se a bio contiver o código gerado.
- `GET /api/auth/me`: verifica a sessão assinada no cookie HttpOnly.
- `POST /api/auth/logout`: encerra a sessão no navegador.
- `GET /api/health`: verificação de saúde do servidor.

A API Key com `group:write` não é usada nesta versão: a leitura da bio pública não precisa dela. Não coloque chaves secretas no `index.html` nem as envie para o GitHub.

## Limitações importantes
- A bio precisa estar pública e atualizada; a alteração pode demorar para aparecer pela API do Roblox.
- Os códigos pendentes ficam em memória e são apagados quando o servidor reinicia. Para vários servidores ou uma implantação maior, use Redis ou banco de dados.
- Esta versão comprova o controle do perfil; não implementa promoções, treinamentos, divisões ou CGEx.
- O código está preparado para publicação, mas a verificação final precisa ser feita depois de implantar no Render.
