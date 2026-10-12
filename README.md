# EB Manager — Emerson

Aplicação Node.js com login por verificação real da bio pública do Roblox e módulo de patentes/promoções do grupo. Todos os arquivos ficam na raiz.

## Render

- Tipo: Web Service
- Build Command: `npm install`
- Start Command: `npm start`
- `SESSION_SECRET`: segredo aleatório com pelo menos 32 caracteres (obrigatório para a sessão)
- `ROBLOX_API_KEY`: chave Open Cloud do Roblox guardada somente nas variáveis Environment do Render; deve ter a permissão `group:write` para o grupo correto. Nunca coloque essa chave no GitHub nem no HTML.
- `ROBLOX_GROUP_ID`: `13616747` (grupo do Exército Brasileiro)
- `ADMIN_USER_IDS`: IDs de usuário Roblox autorizados a administrar promoções, separados por vírgula. Exemplo: `5657784222` para autorizar a conta usada no teste da tela de login.

## Patentes e promoções

O módulo permite pesquisar um nome de usuário, consultar a patente atual e aplicar uma mudança para uma patente acima dela por meio de Roblox Open Cloud. A leitura da associação aceita tanto o campo singular `role` quanto listas de cargos em `roles`, para tolerar formatos diferentes de resposta da API. A API Key fica no servidor e as rotas conferem a sessão Roblox e a lista de IDs administrativos. O próprio Roblox também aplica suas permissões: a chave precisa estar configurada para o grupo e o dono da chave precisa poder atribuir a patente. A conta autenticada não pode promover a si mesma.

A lista de atividade recente é mantida na memória do processo e pode ser apagada em reinicializações/deploys. Ela não substitui o log de auditoria oficial do grupo Roblox.

## Login

1. Digite o nome de usuário Roblox.
2. Copie o código temporário para a bio pública do perfil.
3. Clique para verificar; a sessão autenticada abre o painel.

## Segurança

Nunca envie sua API Key no chat nem a salve em `server.js`, `index.html` ou no repositório. Se uma chave já foi publicada, revogue-a e crie outra.
