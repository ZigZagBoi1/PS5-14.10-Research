# P675 NOTES — status seed st=4 (2026-11-11 22:25)

## Registro de determinismo do p673 (log `beacons_034835cf`)

10/10 cargas limpas, TODAS idênticas na estrutura:
`R0 hit=lane 1` (sempre lane 1), `T=0x10001ca9a0` (constante na geração),
`rc=1`, W micro-drift (`0x10007e6780-0x10007e6c90`), LANE-telemetry:
**apenas `owner=r0 lane=1`** stamped — rodadas >0 nunca aterrissam lane (R1
parity-missa, morte R2 come a janela). OBS: `opc=0 rc=1 st=0 Tsame=y`.

**LEI #8 (nova)**: o reclaim é **totalmente determinístico end-to-end
dentro de uma geração de WebProcess** — mesmo lane, mesmo T, mesmo rc, toda
carga. Consequência: o dataset de distância entre lanes multi-rodada está
BLOQUEADO pela morte R2; self-address (Δ = T − laneVA, constante por geração
porém não-medível de JS) exige sobrevivência R2+ primeiro.

## A análise m_status (citações) — veredito: **st=4 (Failure)**

Leituras de m_status nos caminhos teardown/remove/purge/matching:

| Leitura | Onde | Efeito com Failure(4) |
|---|---|---|
| `pump()` early-return | CSSFontFace.cpp:645-647 — `if (status() == Status::Failure) return 0;` | **CURTO-CIRCUITA ANTES de tocar sources/clients/status-transitions** — o caminho mais protetor possível |
| `computeFailureState()` | CSSFontFace.cpp:470-478 — `if (status() == Failure) return true;` | `CSSFontFace::font()` retorna nullptr cedo em :726-728 **sem** rodar pump/loop de sources |
| `fontFace()` candidate skip | CSSFontFaceSet.cpp:466-467 — `if (candidate.status() == Status::Failure) continue;` | faces Failure são puladas na seleção de candidatos (matching do round 2 nem as toca) |
| `check()` | CSSFontFaceSet.cpp:440-445 | Pending/Loading → false; Failure → conta como "pronta" (sem perigo) |
| `remove()` activeCount | CSSFontFaceSet.cpp:274-275 — decrementa SÓ para Loading/TimedOut | **Failure NÃO decrementa** — sem risco de underflow |
| `add()` activeCount | CSSFontFaceSet.cpp:213-214 — incrementa SÓ para Loading/TimedOut | Failure NÃO incrementa — neutro |

**Runner-ups rejeitados (com causa)**:
- **Success(3)**: não pula nada em pump (cai no loop de sources), e
  `initializeWrapper`/wrapper-replay re-emitem eventos de estado
  (CSSFontFace.cpp:495-515) — trabalho extra, zero benefício de skip.
- **Loading(1)/TimedOut(2)**: ativamente NOCIVOS — `remove` :274-275
  decrementa activeCount para eles (underflow se removida de novo);
  `fontFace()` :466 não as pula (entra como candidata).
- **Pending(0)**: é o status natural de hoje (st82=0) — controle.

**Caveat honesto (estrutural)**: a cadeia de destrutores
(timer → wrapper → ~HashTable → sources → ranges → families → variant)
**não lê m_status** — destruição é dirigida por refcount
(RefCounted.h:129-144/:187-192). Se o killer R2 for puramente
refcount→dtor, st=4 não muda nada (outcome b). MAS se QUALQUER caminho
intermediário na janela R2 (style-rebuild pedindo font() à face velha,
matching → `face.get().load()` → pump em FontFaceSet.cpp:169) tocar a face
forjada ANTES da destruição, Failure curto-circuita esse toque antes de
andar em sources/clients forjados. Zero writes LATE: lei 6 intacta por
construção (o engine não sobrescreve +0x82 — prova p668/669/673: st82
permaneceu 0 seedado 0; stamps do engine são só +0x58/+0x68/+0x00-inc).

## Design (`probes/phase13_webkit/p675-status.html`)

Base p669 exata (seed /size, rc NÃO semeado, keepspray, OBS, beacons batch,
ROUNDS=8, **zero writes LATE**) + delta único: `dv.setUint8(0x82, 4)` no
spray-time de toda lane. Assinatura esperada no R0-line: `st82=4` (e o
experimento natural: OBS mostra se o engine reescreve st em algum momento —
até hoje nunca escreveu +0x82).

## Árvore de decisão

```
6 cargas de /p675 (= raiz):
(a) ALIVE end-r8-status4
    => seed de status desarma o caminho R2 => STABLE FORGE. Telemetria LANE
       multi-rodada vira possível dentro do sobrevivente => dataset Δ
       (self-address) na sessão seguinte — o bloqueio da lei 8 cai.
(b) morte R2 inalterada (R1 passa, R2 não)
    => status não é lido no caminho killer (dtor puro refcount) => próximos
       oráculos: +0x48 sources (vector vazio BEM-FORMADO no spray-time —
       pump itera sources em não-Failure; prioridade alta), +0x60 opCount
       pre-seed grande (prior baixa — p669 mostrou opc nunca mexido), ou
       aceitar e pivotar de volta ao spray-time rc (linhagem p674).
(c) fenótipo NOVO (ex.: R1 vira HIT — fontFace() pula candidatos Failure
    muda o matching; ou morte muda de janela)
    => status lido em lugar inesperado — cruzar DUMP1/OBS (st82 muda de 4
       para outro valor = engine ESCREVEU +0x82 pela primeira vez) antes de
       qualquer variante.
```

## Protocolo

1. serve.py restartado; `/` e `/p675` servem p675-status; `/p674 /p673
   /p672 /p671 /p670 /p669 /size /zero /skip /p666 /p667 /nosp /sp12`
   preservados.
2. **6 cargas de `https://192.168.50.45/`** — **≥32 s por carga**.
3. Grep: `P675-R0 .* st82=4` (seed sobreviveu ao reclaim), `P675-R1`
   (hit-vs-miss — phenotype change = status lido no matching!),
   `P675-R2`/`R3+` (sobrevivência), `ALIVE end-r8-status4` (**vitória**),
   OBS `st=` mudando de 4 (primeira escrita do engine em +0x82 = dado novo).
