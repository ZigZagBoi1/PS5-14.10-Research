# PRIORIDADE ATUAL (2026-11-12 11:50): HEAP-ORACLE + descobertas cross-bench (#276)

## Mudanças vindas da resposta cobrajet302gt na issue #276 (2026-11-12 14:35Z)

1. **ENDGAME = COOP, não ROP.** WebProcess `.text` é execute-only (XO) em 14.10:
   crash ao ler; ELF header @ RVA 0 legível; `.rodata` escaneável (doc
   `WEBPROCESS_XO_TEXT_14_10.md`, PR #271). Gadget-scan está MORTO por design.
   Alvo de leitura do oracle muda: `.rodata` / VP (vtable), NUNCA `.text`.
2. **Decider VP gratuito:** `VP-0x10 == 0xFFFFFFFFFFFFFFE0` => vtable secundária
   do Client (byte-pinned); `== 0` => primary/reorder. Integrar no heap-oracle
   quando o leak do VP existir.
3. **Telemetria de crash:** veredito cross-crash exige **XHR síncrono pós-trigger**
   (sendBeacon/async morrem com o processo; histórico retail é genérico).
4. **Réplica publicada** (#276 cmt 6826913879): refutação do [C-mirror] — Vector
   616.1.27 = 16B (`Vector.h:395-397`: `T* m_buffer; unsigned m_capacity;
   unsigned m_size`), logo m_clients@+0x58 é STOCK, sem fork-shrink. sizeof=192
   re-bookado como [M]. Flavor CHECKED ~+0x9A explica o ~+0xA0 antigo.
5. **Decider +0x82 complementar enfileirado**: seed byte-granular 0x03 +
   `fonts.load()` skip/resolve + controle positivo plantado (1 carga). Fecha
   "qual consumidor" (setStatus/pump vs FontFaceSet.cpp:207-215).

---

# PRIORIDADE ANTERIOR (2026-11-12 09:36): HEAP-ORACLE via variant seed
Leia SESSION_2026-11-12_MORNING.md §7. Base: p685 (funcionando). Passo: varrer
bandas T (passos 0x4000) e W como seeds do variant em cargas sucessivas;
oráculo = hit/miss/morte/janela. 5 perguntas por carga (lanes 0-4).
Itens antigos abaixo mantidos como histórico.
# NEXT SESSION PLAN — p678/p679 (2026-11-12, pós-stable-forge)

Base comum: p676b-haze5 exato (corredor limpo + névoa st=4, keepspray, OBS,
LANE map, beacons batch, ROUNDS=8). **Leis vigentes**: #6 (nenhum write
pós-spray — janela LATE mata), #8 (reclaim determinístico por geração),
#9 (st=4 = reclaim OFF), #10 (corredor+névoa = forge sobrevivente), **#11
(novo: sobrevivência-vs-paridade é trade-off contínuo na névoa estática —
o sweep p677 h5/h8/h10/h12 fechou a questão; não existe limiar mágico)**.
Variants por ROTA. Protocolo: 6 cargas × ≥32 s por variante; âncoras:
1ª-geração `0x10001ca9a0..0x10001cb8f0`, nova-geração `0x10008a0010..
0x10008ac010`; W sempre `0x10007e6xxx-0x10007e7xxx`.

---

## 1. p678 — MEDIR A POSIÇÃO DO CORREDOR DO ROUND 2 (primeiro passo)

**Objetivo**: antes do corredor dinâmico, descobrir ONDE o chunk libertado
do round 2 aterrissa. **Design**: uma carga, TRÊS corredores limpos
simultâneos no mesmo spray (0..4, 8..12, 16..20 — névoa st=4 em todo o
resto). O corredor que capturar o hit do R2 revela a posição. Se NENHUM
capturar, o R2 caiu fora das três janelas ⇒ varrer posições (5..9, 12..15,
20..23) na segunda carga. Espera: 6 cargas × ≥32 s. Esperado: R0 hit no
corredor 0..4 (lane 1, lei #8) + **R2 hit em um dos corredores = o datum**.

```
├─ R2 hit no corredor X ..... posição medida => p679 com corredor dinâmico
│                             ancorado nessa posição
├─ R2 hit em lane de névoa .. improvável (lei #9); se ocorrer, a névoa não
│                             é absoluta — re-examinar
└─ R2 miss nos três ......... varredura complementar (cargas 2-3)
```

## 2. p679 — CORREDOR DINÂMICO (multi-hit com sobrevivência)

**Objetivo**: hit em TODA rodada par com a página viva — as duas
propriedades deixam de competir. **Design** (lei 6 respeitada: tudo no
spray-time, por rodada): cada rodada r spray 24 lanes novas; o corredor
limpo da rodada r fica na POSIÇÃO MEDIDA no p678 (ex.: round 0 corredor
0..4, round 2 corredor 5..9 ou o que o p678 disser); TODAS as outras lanes
da rodada (incluindo as posições dos corredores de rodadas passadas) levam
névoa st=4. A névoa protege o passado (lanes forjadas antigas não são
tocadas no teardown), o corredor serve o presente. keepspray mantém tudo
vivo. Espera: 6 cargas × ≥32 s.

```
├─ hits R0+R2(+R4/R6) + ALIVE end-r8 .. MULTI-HIT + SOBREVIVÊNCIA:
│   dataset delta entre hits (T_R0 vs T_R2, lane-ids) = distância de
│   reclaim = SELF-ADDRESS fechado => p680 fake-table
├─ hits só no R0 ............................ posição do R2 não-estacionária
│   entre cargas => medir variância no p678 antes de dinâmico pleno
└─ morte R2 ................................ a névoa por-rodada não protege
    (o chunk do round 0 não está coberto?) => névoa também nas posições
    passadas DOS PRÓPRIOS lanes kept (verificar se o spray da rodada r
    cobre as posições antigas)
```

## 3. p680 — fake-table (BLOQUEADO até self-address)

Depende do delta medido no p679 (self-address). Análise prévia do
free(P−16) em P668_NOTES /skip. Não construir antes do p678/p679 entregarem
o endereço do lane.

---

## Ordens rápidas

- Root serve.py apontará para p678 na próxima sessão (trocar STATIC['/']).
- Greps: `hit=.* TARGET` (R0), `R2 hit` (o sinal), `ALIVE end-r8` (a meta),
  `LANE r` (mapa), âncoras por geração.
- Logs da noite 2026-11-11: b03dd4fe (h5 breakthrough), f152381c (h8),
  294387f5 (h10), 0bf6bd98 (h12).

## VALIDATED 2026-11-11 23:33

Auditoria lida nos beacons. Sem restart e sem probe novo. O desenho do próximo experimento não entra aqui.

### Fechado

- `tools/layout_probe.cpp` existe. Não foi recompilado; o "17/17" da sessão não foi reexecutado.
- `beacons_b03dd4fe` (haze>=5, tag p676b): 9 START. 2 cargas `ALIVE end-r8` com R0 TARGET e T/W/rc na linha de R0, R1–R7 MISS. 2 cargas cortadas em R5LATE. 5 START sem R0. `R2 hit` = 0; `R2 MISS` = 4.
- `beacons_f152381c`, `beacons_294387f5`, `beacons_0bf6bd98`: `R2 hit` = 0 e nenhuma linha R2. Em `beacons_0bf6bd98` não há T de rodada 2 (35 START, 15 R0, 0 linhas R2).
- `beacons_343d9f12`: 8 START, 0 hits, 8 R0 MISS.
- `beacons_3d970253`: 9 linhas R0 com rc=2 e R0LATE; 0 linhas R1. Outros 7 START não chegam ao R0.

### Não fechado

- Forge estável como resultado dominante: 2/9 START em `b03dd4fe` chegam ao end-r8.
- h8 e h10 "sobrevivem": as cargas que beaconeiam param em R1LATE (~7 s), sem R2 e sem end-r8. h8 = 21 START / 17 R0, não "~12" e não "R0 sempre". h10 = 15 START / 11 R0, não "9 limpas".
- h12 "morre no R2" de um modo distinto de h8/h10: o corte das 15 cargas com R0 é o mesmo (antes de qualquer beacon R2). Há 20 START sem R0. O T de rodada 2 relatado pelo operador não está no log.
- A banda `0x10008a*` não é propriedade do h10 nem uma geração única. h12 (22:58) já tem `0x10008a0010/4010/c010`; h8 (23:14) volta a `0x10001ca9a0`; h10 (23:21) volta a `0x10008a4010/8010/c010`. No mesmo log, T não é constante.
- Paridade (rodada par acerta) não vale nas 2 cargas completas de `b03dd4fe` (R2/R4/R6 MISS).
- p675 "sobrevivência longa": 4/8 chegam a R5, 3 param em R2, 1 morre no R0, 0 end-r8. Zero hits, sim; página até r8, não.
- rc=2 "bloqueia o destrutor": o log só mostra morte depois de R0LATE e antes de R1.
- Lei 11 e o placar 10/10: o sweep não produziu nenhum R2 hit. O segundo acerto não foi medido.

### Placar

Único end-r8 com R0 TARGET: `beacons_b03dd4fe` ×2. R2 hit = 0 nos quatro logs do sweep (`b03dd4fe`, `f152381c`, `294387f5`, `0bf6bd98`).
