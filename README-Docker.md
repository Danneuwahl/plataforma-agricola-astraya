# ASTRAYA Plataforma Agronômica — Docker

## Serviços

- `app`: aplicação React/Vite compilada e servidor Express em Node.js, publicada na porta configurada em `APP_PORT` (padrão `3000`).
- `db`: PostgreSQL 16, acessível apenas pela rede interna do Compose.
- `postgres_data`: volume nomeado para manter os dados do PostgreSQL após recriações dos containers.

## Iniciar

1. Instale Docker Engine e o plugin Docker Compose.
2. Na raiz do projeto — a mesma pasta que contém `compose.yaml` — copie `.env.example` para `.env` e edite esse arquivo:

   ```bash
   cp .env.example .env
   nano .env
   ```

3. No `.env`, defina uma senha única e forte em `DB_PASSWORD`. Informe `GEMINI_API_KEY` para habilitar o assistente de IA.
4. **Defina o usuário administrador inicial no próprio `.env`**, na raiz do projeto. Descomente ou acrescente estas três linhas e substitua pelos seus dados:

   ```env
   ADMIN_NAME=Nome do Administrador
   ADMIN_EMAIL=seu-email@dominio.com
   ADMIN_PASSWORD=coloque-uma-senha-forte-com-12-caracteres-ou-mais
   ```

   `ADMIN_EMAIL` será o usuário usado na tela de login; `ADMIN_PASSWORD` será a senha inicial. Não é necessário inserir esse usuário manualmente no PostgreSQL: o servidor cria a conta com role `admin` na primeira inicialização. Se o email já estiver cadastrado, a inicialização promove essa conta, mas mantém a senha que ela já tinha. Sem essas variáveis, o cadastro público cria contas `reader`; um administrador pode promovê-las pelo painel.
5. Se publicar por HTTPS atrás de um proxy, defina `COOKIE_SECURE=true`. Em HTTP local, mantenha `false`.
6. Inicie os serviços:

   ```bash
   docker compose up -d --build
   ```

7. Abra `http://localhost:3000` (ou a porta definida em `APP_PORT`) e entre com o `ADMIN_EMAIL` e `ADMIN_PASSWORD` definidos no `.env`. Para consultar a saúde da aplicação e conexão com o banco, use `http://localhost:3000/api/health`.

Comandos úteis:

```bash
docker compose ps
docker compose logs -f app db
docker compose down
```

`docker compose down` preserva o volume de dados. Para apagar também os dados persistidos do PostgreSQL, é necessário executar explicitamente `docker compose down -v` — essa ação é destrutiva.

## Atualizar uma instalação existente em `/opt/plataforma-agronomica`

Este procedimento presume que o ZIP de entrega foi copiado para `/opt/ASTRAYA-Plataforma-Agronomica-Docker-RBAC.zip`. Execute como `root` (ou entre com `sudo -i`). Ele atualiza os arquivos da aplicação sem substituir um `.env` existente e sem remover volumes Docker. Se o ZIP estiver em outro local, ajuste a variável `ZIP` antes de executar.

Antes de atualizar, gere um backup do banco existente:

```bash
cd /opt/plataforma-agronomica
umask 077
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > "/root/astraya_agronomica_pre_update_$(date +%Y%m%d-%H%M%S).sql"
```

```bash
set -e
ZIP=/opt/ASTRAYA-Plataforma-Agronomica-Docker-RBAC.zip
APP_DIR=/opt/plataforma-agronomica
STAGE="$(mktemp -d /tmp/astraya-update.XXXXXX)"

unzip -t "$ZIP" >/dev/null
unzip -q "$ZIP" -d "$STAGE"
SRC="$STAGE/ASTRAYA---Plataforma-Agronomica-main"
test -f "$SRC/compose.yaml"
mkdir -p "$APP_DIR"

# Salva uma cópia do ambiente atual fora da pasta do projeto.
if [ -f "$APP_DIR/.env" ]; then
  cp -a "$APP_DIR/.env" "/root/plataforma-agronomica.env.$(date +%Y%m%d-%H%M%S).bak"
fi

# Copia/atualiza os arquivos; o ZIP não contém .env e não usamos --delete.
cp -a "$SRC/." "$APP_DIR/"
if [ ! -f "$APP_DIR/.env" ]; then
  cp "$APP_DIR/.env.example" "$APP_DIR/.env"
fi
chmod 600 "$APP_DIR/.env"

# Remove somente artefatos locais de npm/build; não toca no volume do PostgreSQL.
rm -rf "$APP_DIR/node_modules" "$APP_DIR/dist"
rm -rf "$STAGE"
cd "$APP_DIR"
```

Revise o ambiente antes de iniciar:

```bash
cd /opt/plataforma-agronomica
nano .env
```

Mantenha `DB_NAME` e `DB_USER` iguais aos usados pelo banco já existente e mantenha `DB_PASSWORD` igual à senha atual do usuário PostgreSQL (`astraya_app`). No caso de um volume já inicializado, mudar `DB_PASSWORD` somente no `.env` **não** altera a senha dentro do PostgreSQL; se a senha foi trocada com `\password astraya_app`, atualize o `.env` com exatamente essa mesma senha. Deixe `APP_PORT=3000` para conservar a porta publicada, configure `COOKIE_SECURE=true` se o acesso for HTTPS e informe a chave `GEMINI_API_KEY` se utilizar o assistente de IA. Para provisionar/promover o administrador inicial, configure `ADMIN_EMAIL`, `ADMIN_NAME` e `ADMIN_PASSWORD` conforme explicado acima; para um usuário já existente, a promoção pelo `.env` não troca a senha atual dessa conta.

Antes do `up`, verifique se existe algum processo independente do Compose ocupando a porta 3000. Se aparecer um Node antigo, encerre-o pelo gerenciador que o iniciou (systemd/PM2 ou equivalente); não mate um processo desconhecido. Um container antigo do próprio Compose pode permanecer ativo — o `up` abaixo atualiza o serviço.

```bash
cd /opt/plataforma-agronomica
ss -ltnp | grep ':3000' || true
docker compose config -q
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 app db
curl -i http://127.0.0.1:3000/api/health
```

O servidor aplica a migração dos perfis ao iniciar. **Não execute `docker compose down -v`, não remova `astraya_agronomica_postgres_data` e não altere o nome do volume**: esses passos podem apagar os registros existentes.

## Autenticação e dados por usuário

O app oferece cadastro e login. Senhas são armazenadas com `scrypt`; a sessão usa cookie `HttpOnly` e token aleatório, persistindo apenas seu hash no PostgreSQL. A role é definida e validada no servidor; não pode ser elevada pelo navegador. A migração do schema transforma contas antigas com role `user` em `operator`, mantendo a capacidade de edição dos próprios dados.

### Perfis e painel administrativo

- **Admin:** botão **Painel** no cabeçalho; cria contas, atribui perfis, ativa/desativa usuários, redefine senhas e abre os dados de qualquer conta para leitura ou edição. A desativação encerra sessões e preserva os registros. O sistema impede rebaixar ou desativar o último administrador ativo.
- **Operador:** cria, lê, edita e exclui registros apenas da própria conta. Não administra usuários nem os catálogos reservados ao admin.
- **Leitor:** consulta somente os próprios dados. Alterações são bloqueadas no servidor, mesmo que alguém tente chamar a API diretamente.
- **Cadastro público:** toda nova conta começa como `reader`; o admin pode alterá-la para `operator` no painel. Usuários criados pelo formulário do painel recebem o perfil selecionado.

Ao subir a nova versão, o servidor ajusta o schema automaticamente: cria o campo de status e converte o role antigo `user` para `operator`, preservando contas e registros existentes. Essa migração não exige apagar nem recriar o volume PostgreSQL.

As coleções da aplicação são armazenadas em `app_user_data` com chave composta pelo dono dos dados e nome da coleção. Operadores e leitores só acessam o próprio workspace. A identidade efetiva vem da sessão; a rota aceita alvo diferente exclusivamente para um admin autenticado, para suportar o painel. O tema visual continua como preferência local.

Na primeira autenticação neste navegador, se a conta ainda não tiver coleções no banco e o navegador não estiver marcado como pertencente a outra conta, os dados legados de `localStorage`/IndexedDB são enviados em uma única operação transacional para essa conta. A cópia local é mantida como contingência. Se trocar para uma conta diferente no mesmo navegador, os dados locais da conta anterior não são importados; o cache é substituído pelo conteúdo da conta autenticada.

Após a carga inicial, alterações são gravadas automaticamente no PostgreSQL e também mantidas localmente como cache. O endpoint `/api/health` verifica a conexão com o banco. A aplicação mantém coleções como JSONB, com limite de 20 MB por coleção; a importação legada agregada também tem limite de 20 MB. Fotos já armazenadas como base64 contam para esses limites. Como cada gravação substitui uma coleção inteira, edições simultâneas da mesma conta e coleção em mais de um navegador são do tipo “última gravação vence”; use uma sessão de edição por conta ou atualize a página antes de editar no outro dispositivo.

Por segurança, a porta do PostgreSQL não é publicada no host. A aplicação acessa o serviço pelo nome `db` dentro da rede Docker.

## Backup do PostgreSQL

Para gerar um dump lógico:

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > astraya_agronomica.sql
```

Para restaurar em uma instalação já inicializada, faça primeiro um backup do estado atual e então:

```bash
cat astraya_agronomica.sql | docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

Guarde `.env` e dumps fora do repositório e com permissões restritas.
