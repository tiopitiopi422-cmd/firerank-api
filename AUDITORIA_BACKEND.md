# AUDITORIA PROFUNDA — FIRE RANK BACKEND RAILWAY V4.2

## Resultado executivo

O código recebido foi analisado como backend Node/Firebase e não apenas como arquivo JavaScript.

### Validação estrutural

- arquivo original: ~9.150 linhas;
- sintaxe original: `node --check` passou;
- nenhuma função nomeada duplicada encontrada;
- nenhum `TODO`, `FIXME`, `HACK` ou `XXX` encontrado;
- 22 rotas HTTP identificadas;
- autenticação Firebase Admin presente;
- mídia privada/protegida presente;
- pagamento/ledger/entitlements/boosts presentes;
- healthcheck existente, porém foi endurecido nesta versão.

## Pontos bons mantidos

### Autenticação

- ID Token é validado no servidor;
- token revogado é rejeitado;
- ações protegidas rejeitam conta anônima;
- App Check pode ser exigido por configuração.

### Vendedor e produto

- backend valida elegibilidade do vendedor;
- backend valida vínculo com loja;
- preço de produto é validado no servidor;
- produto afiliado valida HTTPS e domínio;
- conta/loja privada não deve gerar projeção pública;
- índices públicos são gravados pelo backend;
- mídia é limitada e processada no servidor.

### Mídia

- tipo real da imagem é inspecionado;
- limite de tamanho existe;
- Sharp normaliza imagem;
- detail/thumbnail são WebP;
- bucket é privado;
- acesso privado passa pelo backend;
- tokens de entrega são HMAC.

### Pagamentos

- preço de Verificado não vem livremente do cliente;
- preço de Boost é resolvido pelo servidor;
- o webhook consulta o pagamento real no Mercado Pago;
- valor e moeda são conferidos;
- `external_reference` amarra pagamento ao request interno;
- ledger usa eventos determinísticos;
- reversão de pagamento desativa/revisa benefício.

### Auditoria

- existe `audit_logs`;
- eventos financeiros são separados;
- notificações não carregam segredos.

## Correções feitas no Ultra Final 01

### CRÍTICO — schema

O backend anterior escrevia `4.1.0` em `public_config/api`. O banco atual já opera com configuração V4.2.

Corrigido para uma constante única:

```text
FIRERANK_SCHEMA_VERSION=4.2.0
```

### CRÍTICO — domínio antigo Render

Havia fallback permanente para um domínio Render específico antigo.

Corrigido:

1. `APP_BASE_URL` explícito, se informado;
2. senão `RENDER_PUBLIC_DOMAIN`;
3. local host somente para ambiente local.

Em produção, `public_config/api` não é sobrescrito com URL HTTP/local.

### CRÍTICO — assinatura do Mercado Pago

O webhook anterior aceitava uma notificação sem autenticar `x-signature`.

Corrigido com `WebhookSignatureValidator` do SDK oficial e:

```text
MERCADO_PAGO_WEBHOOK_SECRET
```

Quando Mercado Pago está habilitado em produção, ausência do secret torna o módulo indisponível.

### CRÍTICO — idempotência de fulfillment

Risco anterior:

1. webhook gravava evento;
2. ativação de entitlement/boost acontecia depois;
3. uma falha intermediária podia deixar o evento existente;
4. retry podia ser ignorado;
5. pagamento aprovado poderia ficar sem benefício.

Corrigido com:

```text
payment_processing/{requestId}/{eventId}
```

e transaction/lock com recuperação de lock antigo.

Além disso:

- entitlement não é estendido duas vezes para o mesmo request;
- boost não é ativado duas vezes para o mesmo request;
- notificação após concessão é best-effort;
- falha de notificação não provoca nova concessão.

### ALTO — segredo de mídia

Antes, na ausência de `MEDIA_TOKEN_SECRET`, o segredo podia derivar da private key da service account.

Problema: rotação da service account poderia invalidar URLs assinadas antigas.

Agora:

- produção exige `MEDIA_TOKEN_SECRET` explícito e estável;
- fallback derivado existe somente fora de produção.

### ALTO — CORS

Antes, `CORS_ALLOWED_ORIGINS` vazio liberava qualquer Origin de navegador.

Agora:

- chamada sem Origin continua aceita (Android/iOS/server);
- navegador em produção precisa estar na allowlist;
- desenvolvimento continua permissivo se não houver lista.

### ALTO — healthcheck

Antes, `/health` podia responder HTTP 200 mesmo com `ok:false`.

Agora:

- dependência crítica indisponível => HTTP 503;
- saudável => HTTP 200;
- Render usa `/health`.

### MÉDIO — proxy

Adicionado:

```js
app.set("trust proxy", 1)
```

para que `req.ip` faça sentido atrás do proxy do Render.

## Problemas que permanecem fora deste pacote

Eles são importantes, mas não foram simulados como “prontos” porque exigem integração de produto completa.

### 1. Backend FireRank inteiro ainda não está completo

Ainda não há API completa neste arquivo para:

- checkout/pedidos;
- reserva de estoque;
- transições completas de pedido;
- entregador/state machine;
- chat;
- suporte humano Plus/Pro;
- reports/moderação/appeals;
- reviews backend-authoritative;
- AI Gateway;
- exportação/exclusão LGPD;
- ingestão de analytics;
- notificações push FCM reais;
- validação de compra Google Play.

### 2. Atualização de produto local é parcial

A criação de produto local possui validações mais completas do que o endpoint genérico de update.

Não foi feita uma alteração destrutiva automática em inventory/variants porque isso pode:

- apagar estoque;
- quebrar reservas;
- afetar pedidos já existentes.

A atualização completa de variantes/estoque precisa de uma state machine/migração própria.

### 3. Upload abandonado pode deixar mídia órfã

A sessão de upload tem TTL lógico, mas o objeto gravado no bucket pode permanecer caso o usuário abandone a criação.

Próxima fase recomendada:

```text
media_upload_sessions
+ cleanup de objetos não finalizados
```

### 4. Manutenção ainda consulta conjuntos ativos

`expireBoosts()` e `expireSubscriptions()` ainda varrem os itens ativos retornados pelas queries.

Para volume grande, criar índice temporal próprio por expiração e processar em lotes.

### 5. Rate limit é em memória

Bom para:

- um processo;
- um replica;
- fase inicial.

Não é suficiente para:

- múltiplas réplicas Render;
- rate limit global.

Próxima fase: Redis/Valkey ou limiter central.

### 6. Play Billing ainda não é prova de compra

`ENFORCE_GOOGLE_PLAY_BILLING` usa informação da plataforma do cliente para bloquear o checkout web.

Isso não substitui:

- Google Play Billing real;
- purchase token;
- validação server-side;
- acknowledgement;
- RTDN;
- tratamento de refund/cancel.

### 7. Estado suspended/banned não possui contrato de storage confirmado nesta revisão

A arquitetura define estados:

```text
active
suspended
banned
deleted
```

mas não foi inventado um caminho RTDB novo para o middleware sem confirmar o contrato definitivo do estado de conta.

Não é correto adicionar uma leitura para um path hipotético e bloquear usuários errados.

### 8. Observabilidade externa

Logs existem, mas ainda faltam como integração real:

- alertas;
- uptime contínuo;
- dashboard;
- alertas de custo;
- monitoramento de webhook/fila.

## Sobre “pronto para milhares”

O pacote melhora fortemente segurança e confiabilidade, porém não deve ser rotulado como pronto para milhares de usuários até concluir:

- testes de Rules em Emulator;
- STAGING;
- billing sandbox;
- App Check observado/enforced;
- rate limit central para múltiplas réplicas;
- jobs de manutenção paginados;
- teste de backup e restore;
- monitoramento.

## Status honesto

### Pronto para Git

SIM, após gerar `package-lock.json` com `npm install` e revisar `git status`.

### Pronto para criar serviço Render

SIM.

### Pronto para apontar o APK ao novo Render

SOMENTE quando `/health` retornar `ok:true` e os fluxos usados pelo APK forem testados.

### FireRank inteiro “produção final”

AINDA NÃO.

Este pacote deliberadamente não marca como concluídas funções que ainda não passaram pela cadeia:

```text
banco -> rules -> backend -> Flutter -> integração -> compilação -> teste -> segurança
```
