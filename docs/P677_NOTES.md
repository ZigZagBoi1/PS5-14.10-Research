# P677 NOTES — threshold de névoa: sobrevivência × paridade (2026-11-11 22:50)

## BREAKTHROUGH p676b (log `beacons_b03dd4fe`) — STABLE FORGE ACHIEVED

**Primeira sobrevivência FULL de 8 rodadas COM forge ativo na história do
projeto** — 2 cargas completas:
`R0 hit=1 TARGET T=0x10001cb0d0 W=0x10007e61d0/6210 rc=1` (corredor limpo
0..4, alvo lane 1) → R1..R7 MISS todos vivos → `SUMMARY rounds=8 kept=8` →
**`ALIVE end-r8-selective`** (×2; âncoras cb0d0 nas duas completas + ca9a0
na parcial). Névoa (lanes ≥5, st=4) NUNCA tocada — nenhum LANE com st=4 no
mapa. Mecanismo provado (lei #10): **o engine só reclama dentro de
corredores limpos; névoa st=4 é pulada** — e a sobrevivência veio da névoa
(delta vs /size sem névoa: morte R2).

**LEI #10**: corredor limpo + névoa st=4 = reclaim seletivo SOBREVIVENTE.

## O problema: paridade quebrada

No p676b, R2/R4/R6 (que a lei #1 dizia hitar) deram MISS. Análise: com
apenas 5 lanes limpas (0..4) por rodada, o chunk libertado da rodada r>0
não encontra taker limpo — o lane 1 determinístico (lei #8) era a PRIMEIRA
alocação com freelist virgem; após o round 0 manter 5 lanes, a cabeça da
freelist da size-class moveu. **Corredor estreito = sobrevivência sem
multi-hit.** No p673 (24 lanes todas limpas) R2 hitava — corredor largo =
paridade sem sobrevivência (morte R2). **O limiar de névoa controla as
duas propriedades em direções opostas — busca binária:**

## Design p677 (`probes/phase13_webkit/p677-h{8,12,16}.html`)

Clones exatos do p676b com o limiar de névoa em `i >= 8 / 12 / 16`
(corredores limpos 0..7 / 0..11 / 0..15). Alvo continua lane 1, marcadores
float em todas as lanes, mapa LANE com st=, OBS, beacons batch, ROUNDS=8,
zero writes LATE. START tag distingue (`selective-hN haze>=N r8`).

## Matriz de interpretação

| Resultado por variante | Leitura | Ação |
|---|---|---|
| R0 hit + **R2 hit** + ALIVE end-r8 | **FULL WIN**: sobrevivência E paridade coexistem no limiar | Parar a busca; coletar dataset LANE multi-hit (delta R0→R2 entre lanes = distância de reclaim = **self-address**) |
| R0 hit, R2 miss, ALIVE | Sobrevivência mantida, paridade não — corredor ainda estreito | Descer para corredor MAIS LARGO (h8 corredor 0..7; se já é h8, a paridade precisa de outro mecanismo: corredor dinâmico por rodada) |
| Morte no R2 | Névoa insuficiente — corredor largo demais | Subir limiar (h16; se já é h16, o piso é entre 5 e 16 — testar h6/h10 conforme o lado que cedeu) |
| R0 MISS | Névoa quebrou até o alvo (não esperado — h≥8 é mais folgado que h5) | Re-checar geração/âncora antes de concluir |

## Árvore de decisão da sessão (ordem de execução)

```
1. /h12 (raiz) — 6 cargas x >=32 s:
   ├─ FULL WIN .............. parar; dataset multi-hit (p678): medir
   │                         lane-ids dos hits R0/R2/R4/R6 => delta =>
   │                         self-address => fake-table.
   ├─ R2 miss + ALIVE ....... testar /h8 (corredor mais largo).
   └─ morte R2 .............. testar /h16 (corredor mais estreito).
2. /h8 — se R2 hitar E ALIVE => limiar entre 5 e 12 vence no 8;
   se morte R2 => limiar vencedor está em (8..16) — o /h12/h16 decide.
3. /h16 — se morte R2 mesmo aqui => a sobrevivência do p676b não é
   monotônica no limiar (interação mais fina) — voltar a h5 exato e
   instrumentar a névoa (LANE map com marcadores nas lanes 5+ já presente).
```

## Protocolo

1. serve.py restartado; `/` = `/h12`; rotas `/h8` `/h16` `/p676b /p676
   /p675 /p674 /p673 /p672 /p671 /p670 /p669 /size /zero /skip /p666 /p667
   /nosp /sp12` preservadas.
2. 6 cargas × ≥32 s POR VARIANTE, na ordem /h12 → /h8 → /h16 conforme a
   árvore.
3. Grep por variante: `P677-hN` não existe — beacon continua `P676-` (os
   clones mantêm o tag; o START line distingue: `selective-h12 haze>=12
   r8`). Grep: `START selective-h12`, `hit=1 TARGET`, `R2 hit` (**o sinal
   da paridade**), `ALIVE end-r8-selective`.
