# Matriz de Validação — 4 agentes independentes (2026-11-12, white-box week)
Cross-check: A1 adversarial-source | A2 log-mining | A3 compile-layout | A4 timer+probes
Regra do dia: nenhuma informação chega à bancada sem contra-prova por método distinto.

## Tabela-mestre de veredictos

| # | Claim original (doc/decode) | A1 (fonte adversarial) | A2 (dados device) | A3 (compilado) | A4 (timer/probes) | VEREDICTO FINAL |
|---|---|---|---|---|---|---|
| V1 | variant: P@+0x08, index u32@+0x0C | REFUTADO — geometricamente impossível (overlap 4B); real: P@variant+0, idx u8@variant+8 | CONFIRMA por dados: index nunca 1 em 91 dumps (seeds produzem hi-word≠1) | — (layout variant não coberto) | — | **CORRIGIDO**: P@face+0x10, **index u8 @ face+0x18** (fork no-vptr: variant@+0x08, P@+0x08, idx@+0x10 — ver nota NB abaixo) |
| V2 | HashMap hit ⇒ ~Ref/deref machinery | REFUTADO — mapa K,V ponteiros crus, customDeleteBucket trivial; hit/miss/clear/rehash NUNCA deref | (consistente: sobrevivências com seeds) | CORROBORA (deref é no dtor da face) | — | **MORTO**: HashMap nunca toca P |
| V3 | miss = no-op seguro | CONFIRMADO (find→end→return) | CONFIRMADO (12+ cargas) | — | — | **BANCADO** |
| V4 | hash por valor, P não deref no lookup | CONFIRMADO (PtrHashBase<IntHash>) | — | — | — | **BANCADO** |
| V5 | deref de P ocorre (em algum lugar) | dtor da face, ÚLTIMO membro (~variant) | — | idem (Ref.h:54-61) | — | **BANCADO**: só o ~variant toca P |
| V6 | rc-armor 0xFFFFFFFF estável | CONFIRMADO + bônus: rc==0 também é armor (wrap) | — | CONFIRMADO (compile: rc 0→wrap não deleta) | — | **BANCADO + reforçado** |
| V7 | morte por HIT requer rc==1 | — | — | CONFIRMADO (regra viva rc≥2) | divergência A4 previa rc==2 letal → RESOLVIDA: rc==2 não mata | **BANCADO: só rc==1** |
| V8 | — (nova, A1) | `Ref protect{face}`: remove() faz ref/deref da PRÓPRIA face (rc==0+vptr inválido = crash pré-HashMap) | — | — | — | **NOVO HAZARD**: manter rc≥1 no lane |
| V9 | — (nova, A1) | `families()` hazard: m_families forjado ≠0 é percorrido ANTES do HashMap | — | — | — | **NOVO HAZARD**: manter +0x18 = 0 |
| V10 | — (nova, A1) | ~TimerBase: RELEASE_ASSERT(m_thread == &Thread::current()); m_thread zerado MATA no primeiro dtor | — | — | Timer zerado do forge passou 12+ cargas | **DIVERGÊNCIA EM ABERTO** (ver abaixo) |
| V11 | timer sizeof | — | — | — | 48B (0x90+0x30=0xC0 exato) | **BANCADO 48B** |
| V12 | banda StyleRuleFontFace | isoheap refutado; size-class-16 pool | banda DESCONHECIDA por dados (0 OTHER) | discriminator: typeFlags∈{5,0x25} ∧ rc∈{2,3} | — | **ALVO: size-class-16; achável só com index armado + dump** |

## DIVERGÊNCIA V10 — RESOLVIDA (foreground, pin verificado)

- A1: `RELEASE_ASSERT(...m_thread...)` mataria forge com timer zerado (Timer.cpp:264).
- Pin verifica: assert existe em release; `canCurrentThreadAccessThreadLocalData` = address-compare puro (MainThread.cpp:55-58); **`shouldSuppressThreadSafetyCheck()` retorna FALSE em PlayStation** (Timer.cpp:248-256: IOS/MAC branches only, `#else return false`) — sem suppress.
- CONFLITO com device (p670: 12+ cargas, dtor chegou a ~HashTable com timer zerado).
- **RESOLUÇÃO**: o dtor COMPLETO da face forjada nunca roda nessas cargas. A morte/vida do forge não passa pela cadeia timer→variant; a face não é destruída via `m_faces.clear()` nessas janelas (ou rc não chega a 0). Consequências:
  1. O deref de P no ~variant é inocente **por inexecução** até hoje — não testado;
  2. O lane 0x1 index=1 do p690 NÃO discrimina V10; discrimina o **reclaim-path** (V8: ref()/protect no reclaim — morte imediata R0 ⇒ engine deref no reclaim, não dtor);
  3. Para exercitar o ~variant de propósito (futuro), é preciso FORÇAR a destruição da face (delete() direto com rc==1 via wrapper) — anotado como p691 candidate.

## Nota NB — coordenadas variant nas DOAS frames

- STOCK (com vptr): variant@face+0x10 → P@+0x10, index u8@+0x18 (A1 correto).
- FORK PS5 (vptr dropado, device): tudo −8 → variant@+0x08 → **P@+0x08, index u8@+0x10** — é a frame que o p690 usa (setUint8(0x10,1)). A2 mostrou que nenhum dump histórico tinha index=1 ⇒ braço connection nunca exercitado até hoje; p685 rodou no braço benigno.
- ORDEM DE DTRUIÇÃO REAL (A1, reversa): timer(1º) → wrapper → clients → sources → families → variant(ÚLTIMO). Para chegar vivo ao deref de P: sobreviver timer, clients(T walk), sources, families. Os hazards V8/V9 rodam no `remove(face)` ANTES de tudo.

## Mudanças aplicadas nesta sessão (rastreadas)

| Commit | Mudança |
|---|---|
| 9a52103b | p689/p690/routes (A4) — timer 48B |
| e5e8fc39 | TU StyleRule 16B + erratum deref-face-dtor (A3) |
| 5ba41b99 | era 7616.2.3 / +0x64=maxOp cand (cross-bench #276) |
| e472a35c | fix p690: index u8@+0x10 + descoberta A2 (connection nunca rodou) |

## Runbook de segunda (ordem das cargas)

1. `/p689` (+0x82=3, decider a/b/c/d) — 1 carga, decide status semantics.
2. `/p689b` (+0x94=3) — idem braço B.
3. `/p690` lane3=0x1 index=1: **discriminador V10/V8** — morte imediata R0 ⇒ deref no reclaim-path; sobrevivência ⇒ timer-safe + dtor chega ao ~variant (deref 0x1+4 = wrap/sobrevive, prevê A1).
4. `/p690` arm=1 em lane externa conhecida-nossa (se existir): rc-armor wrap test (prevê sobrevivência).
5. Oracle walk size-class-16 com index=1: candidatos da banda A3 (procura discriminator typeFlags=5).
6. Dump ANTES de semear (recomendação A2): capturar +0x08/idx de face não-reclaimada p/ achar StyleRuleFontFace* real.
7. +0x64 dword read quando live-face legível (maxOp 0x200 branch, pré-registrado #276).
8. VP-0x10 quando oracle ler .rodata-path.

## A2 addendum — teses de banda (para o passo 5)

Nenhuma banda OTHER existe nos dumps históricos. T1/T2/W são as únicas. StyleRuleFontFace* nunca capturado. Estratégia: varredura size-class-16 com index=1 armado (passo 5) OU captura de face viva pré-seed (passo 6). T2 16KB-step map completo no relatório A2 (top: 0x10008a4010×25, 0x100089c010×9...).
