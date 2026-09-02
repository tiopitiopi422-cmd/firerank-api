# FireRank API V4.2 — Railway Ultra Final 01

Pacote de deploy do backend atualmente integrado ao FireRank.

## O que este pacote cobre

O `server.js` mantém o escopo já existente e funcional do backend:

- Firebase Admin / Realtime Database;
- autenticação por Firebase ID Token;
- App Check opcional;
- criação e atualização de produtos;
- upload e entrega protegida de imagens;
- endereços privados;
- recuperação de senha por e-mail;
- Mercado Pago para Verificado e Patrocinado;
- webhook de pagamento;
- ledger financeiro;
- entitlements de verificação;
- boosts;
- manutenção de boosts/assinaturas;
- auditoria;
- healthcheck;
- sincronização de `public_config/api`.

## Correções críticas aplicadas nesta versão

1. Schema do backend atualizado para `4.2.0`.
2. Removido fallback fixo para um Railway antigo.
3. `APP_BASE_URL` passa a usar `RAILWAY_PUBLIC_DOMAIN` quando disponível.
4. `sharp` é dependência obrigatória.
5. `trust proxy` ativado para Railway.
6. CORS em produção passa a falhar fechado para origens de navegador não autorizadas.
7. `MEDIA_TOKEN_SECRET` é obrigatório em produção e não depende mais da rotação da service account.
8. Webhook do Mercado Pago valida `x-signature` com `MERCADO_PAGO_WEBHOOK_SECRET`.
9. Webhook ganhou lock/idempotência de processamento no RTDB.
10. Entitlement/boost não é concedido duas vezes no retry do mesmo pagamento.
11. Notificações pós-fulfillment são best-effort e não provocam concessão duplicada.
12. `/health` retorna HTTP 503 quando uma dependência crítica falha.
13. `railway.json` já aponta o healthcheck para `/health`.
14. Headers incluem `X-FireRank-Schema: 4.2.0`.

## Requisitos

- Node.js 22.x
- npm
- Projeto Firebase configurado
- Railway
- Mercado Pago somente se o módulo de pagamentos estiver habilitado

## Estrutura

```text
server.js
package.json
.gitignore
.env.example
railway.json
README_DEPLOY.md
AUDITORIA_BACKEND.md
VALIDATION_REPORT.txt
APLICAR_NO_REPOSITORIO.ps1
scripts/
  CHECK_BACKEND.ps1
  GERAR_SECRETS.ps1
```

## 1. Aplicar no repositório local

Se o repositório `firerank-api` já estiver clonado no PC, extraia este ZIP e rode:

```powershell
powershell -ExecutionPolicy Bypass -File .\APLICAR_NO_REPOSITORIO.ps1 -RepoPath "C:\CAMINHO\firerank-api"
```

O script:

- confirma que a pasta possui `.git`;
- cria backup timestampado;
- copia os arquivos deste pacote;
- executa `npm install`;
- gera/atualiza `package-lock.json`;
- executa `node --check`;
- executa `npm run check`.

Ele **não faz push automaticamente**.

## 2. Validar antes do Git

Dentro do repositório:

```powershell
npm install
npm run check
```

Depois:

```powershell
git status
```

Confira que **NÃO** aparecem arquivos como:

```text
.env
service-account.json
firebase-adminsdk-....json
qualquer arquivo com chave privada
node_modules
```

## 3. Commit e push

Quando `git status` estiver correto:

```powershell
git add server.js package.json package-lock.json railway.json .gitignore .env.example README_DEPLOY.md AUDITORIA_BACKEND.md VALIDATION_REPORT.txt scripts
git commit -m "FireRank API V4.2 Railway production baseline"
git push
```

## 4. Criar o Railway

No Railway:

1. `New Project`
2. `Deploy from GitHub Repo`
3. selecione `tiopitiopi422-cmd/firerank-api`
4. abra o serviço
5. gere um domínio público em **Networking**
6. abra **Variables**
7. configure as variáveis abaixo
8. faça um redeploy

O backend detecta automaticamente `RAILWAY_PUBLIC_DOMAIN`. Se quiser usar domínio próprio, defina `APP_BASE_URL=https://seu-dominio`.

## 5. Variáveis essenciais

### Obrigatórias para iniciar o backend em produção

```text
NODE_ENV=production
FIREBASE_DATABASE_URL=...
FIREBASE_SERVICE_ACCOUNT_JSON_BASE64=...
MEDIA_TOKEN_SECRET=...
INTERNAL_MAINTENANCE_SECRET=...
```

`INTERNAL_MAINTENANCE_SECRET` não é obrigatório para o processo HTTP subir, mas é necessário para os endpoints internos de manutenção.

### Firebase Storage

Recomendado definir explicitamente:

```text
FIREBASE_STORAGE_BUCKET=...
```

Se ficar vazio, o backend tenta derivar o bucket do `project_id`.

### Mercado Pago

Só configure credenciais reais quando for utilizar/testar pagamentos:

```text
MERCADO_PAGO_PUBLIC_KEY=...
MERCADO_PAGO_ACCESS_TOKEN=...
MERCADO_PAGO_WEBHOOK_SECRET=...
```

Quando `MERCADO_PAGO_ACCESS_TOKEN` existe em produção, o backend exige também `MERCADO_PAGO_WEBHOOK_SECRET`.

Webhook:

```text
https://SEU-DOMINIO/api/mercadopago/webhook
```

No Mercado Pago, configure a chave secreta do Webhook e coloque-a **somente** em `MERCADO_PAGO_WEBHOOK_SECRET` no Railway.

### CORS

Para Android/iOS nativo, normalmente não existe header `Origin`.

Para o FireRank Web, informe as origens autorizadas separadas por vírgula:

```text
CORS_ALLOWED_ORIGINS=https://app.exemplo.com,https://www.exemplo.com
```

Em produção, deixar vazio **não libera qualquer site da internet**.

### App Check

Comece em modo de observação/teste:

```text
REQUIRE_APP_CHECK=false
```

Somente mude para:

```text
REQUIRE_APP_CHECK=true
```

depois que o App Check estiver configurado e validado no app real.

### Google Play Billing

```text
ENFORCE_GOOGLE_PLAY_BILLING=false
```

Não ligue por aparência. O fluxo de recibo Google Play ainda deve ser validado de ponta a ponta antes de enforcement real.

## 6. Converter service account para Base64

Faça isso **no seu computador**. Nunca envie a chave para o chat, GitHub ou README.

PowerShell:

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\CAMINHO\service-account.json")
[Convert]::ToBase64String($bytes)
```

Copie o resultado diretamente para a variável:

```text
FIREBASE_SERVICE_ACCOUNT_JSON_BASE64
```

no Railway.

## 7. Gerar secrets

Neste pacote:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\GERAR_SECRETS.ps1
```

Gere valores separados para:

- `MEDIA_TOKEN_SECRET`
- `INTERNAL_MAINTENANCE_SECRET`

Não versione os valores.

## 8. Healthcheck

Railway já está configurado para:

```text
/health
```

O Railway espera HTTP 200 para considerar o deploy saudável.

Depois de gerar o domínio, acesse:

```text
https://SEU-DOMINIO/health
```

Esperado no deploy pronto:

```json
{
  "ok": true,
  "schemaVersion": "4.2.0",
  "databaseOk": true,
  "storageConfigured": true,
  "mediaProcessorConfigured": true,
  "mediaTokenSecretConfigured": true
}
```

Se `ok` for `false`, não aponte o APK para esse backend ainda.

## 9. Atualização do Firebase

Na inicialização, quando `APP_BASE_URL` é HTTPS, o backend atualiza:

```text
public_config/api
```

com o novo domínio Railway e os endpoints atualmente suportados.

Isso substitui URLs antigas do backend **somente depois que o novo domínio estiver configurado**.

## 10. O que NÃO está sendo chamado de pronto

Leia `AUDITORIA_BACKEND.md`.

Este pacote não inventa endpoints para funções que ainda precisam de implementação de ponta a ponta, como:

- state machine completa de pedidos/checkout/estoque;
- Google Play receipt validation;
- AI Gateway/Gemini;
- suporte humano completo;
- moderação/reports/appeals completos;
- reviews backend-authoritative completas;
- LGPD export/delete completo;
- observabilidade externa/alertas;
- rate limit distribuído multi-réplica.

Esses itens não impedem subir **este backend atualmente integrado**, mas impedem chamar o ecossistema FireRank inteiro de produção final.

## Regra de segurança

Nunca coloque no Git:

- `.env`;
- Firebase service account;
- senha SMTP;
- Mercado Pago Access Token;
- segredo do Webhook;
- `MEDIA_TOKEN_SECRET`;
- `INTERNAL_MAINTENANCE_SECRET`;
- chaves privadas.
