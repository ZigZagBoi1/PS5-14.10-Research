# P676 NOTES — selective-failure forge (2026-11-11 22:40)

## Fenótipo p675 (log `beacons_343d9f12`) — lei #9 candidata

8+ cargas, **ZERO hits em todas**; páginas sobreviveram **R0..R5+**
(sobrevivência recorde do projeto), getters dispararam toda rodada
(gf=0..5). Mecanismo confirmado (salvo alternativa): o seed **st=4
sobrevive no chunk libertado e DESVIA o engine** — matching/purge pulam o
candidato Failure ANTES do reclaim-setup
(`CSSFontFaceSet::fontFace()` continue-on-Failure :466-467; `pump()`
early-return CSSFontFace.cpp:645-647) — sem write de T, sem ref de rc, sem
forge, sem killer.

**LEI #9 (candidata)**: `+0x82` controla se o engine reclama o chunk ou
não. Failure(4) = interruptor de reclaim OFF.

## Reconciliação p674 vs /size (a anomalia rc==2)

| Probe | rc pós-reclaim | R1-window | Morte |
|---|---|---|---|
| /size (p668) | 1 (natural) | passou (R1+R1LATE vivos) | R2 |
| p674 (seed rc=1) | **2** | **morreu pré-R1** | pré-R1 |
| p672 (rc=2 via write LATE) | 2 | morreu pré-R1 | pré-R1 |

Tanto faz o rc=2 chegar por seed spray-time ou por write LATE: **rc==2 é
letal na janela R1**; rc==1 passa. Não é o destrutor (dtor com rc=2 NUNCA
dispara — e a morte foi ANTES do analyze do R1).

**Caça nesta sessão (veredicto: NENHUM guard encontrado)**: procurado
`refCount()>1` / `==1` / `!=1` / `hasOneRef` em Source/WebCore/css — o
único hit é `FontFaceSet.cpp:251` (`pendingPromise->hasOneRef()`, no
PendingPromise, não na face); os demais `size()>1` são do parser/typedom
(irrelevantes). A letalidade do rc==2 **não é explicável estaticamente
neste clone** (candidatos: fork Sony, ou race de timing com o write —
ambos imponderáveis do lado de cá). Consequência prática gravada como lei:
**rc==2 é valor proibido no forge; p677 usará rc=3** (pula o valor letal e
compra DOIS derefs de folga na cadeia de teardown).

## Design p676 v1 (`probes/phase13_webkit/p676-selective.html`)

Base p669 exata (keepspray, OBS, beacons batch, ROUNDS=8, **zero writes
LATE** — lei 6) + seeds seletivos:
- **lane 1 = alvo limpo** (o lane historicamente atingido — lei #8):
  apenas o marcador float `+0x44 = 100+r+1·0.001`; **st fica 0** (reclaim
  permitido); rc NÃO semeado.
- **todas as demais lanes = névoa (haze)**: `+0x82 = 4` + marcador float
  `+0x44 = 100+r+i·0.001` (o mapa LANE revela se alguma lane de névoa é
  alguma vez tocada).
- Telemetria LANE cross-round mantida (padrão p673) + R-line marca
  `TARGET`/`NON-TARGET` no hit.

**Predição**: R0 hit no lane 1 (reclaim-setup completo: T/W/rc = o leak
funciona), lanes de névoa puladas sem perigo. Pergunta crítica: a névoa
st=4 ao redor do alvo muda o killer R2?

## Árvore de decisão

```
6 cargas de /p676 (= raiz):
(a) ALIVE end-r8-selective
    => o padrão seletivo COMPRA sobrevivência por si (o killer precisava
       de múltiplos candidatos atingíveis ou do estado do set ao redor)
       => STABLE FORGE via névoa. Coletar dataset LANE imediatamente:
       o R2 atingindo (paridade) dá o delta entre lanes R0->R2 =
       distância de reclaim = self-address (a lei #8 deixa de bloquear).
(b) morte no R2 (R0 hit no alvo, R1 passa, R2 não)
    => consistente com killer dtor da face forjada única (rc 1->0 no
       teardown) => p677 = seletivo + alvo com rc=3 (NUNCA 2 — lei do
       rc==2). rc=3: ref do engine -> 4; teardown derefs 4->3->2 vivos.
(c) R0 MISS (nem o alvo limpo é reclamado)
    => efeito de proximidade: a névoa st=4 quebrou até o reclaim do alvo
       (o engine talvez avalie vizinhos ou a freelist mude) => p676b:
       névoa só nas lanes 2..5 (alvo isolado por corredor limpo).
```

## Protocolo

1. serve.py restartado; `/` e `/p676` servem p676-selective; `/p675 /p674
   /p673 /p672 /p671 /p670 /p669 /size /zero /skip /p666 /p667 /nosp
   /sp12` preservados.
2. **6 cargas de `https://192.168.50.45/`** — **≥32 s por carga**.
3. Grep: `P676-R0 hit=1 TARGET` (predição central), `P676-LANE` (alguma
   lane de névoa tocada? st= nas lanes do mapa), `P676-R2`+ (sobrevivência
   além do killer), `ALIVE end-r8-selective` (**vitória**).
