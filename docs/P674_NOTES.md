# P674 NOTES — spray-time rc seed (2026-11-11 22:00) — **stable forge attempt: fechar 10/10**

## Evidência da dedução do incremento (logs desta noite)

| Probe | Seed em +0x00 (spray-time) | Readback do rc (pós-reclaim) | Delta |
|---|---|---|---|
| p663-p667 | `100 + round` | `101` (todas as cargas, todas as rodadas) | **+1** |
| p668 /zero | `0` (buffer zerado) | `1` | **+1** |

**Dedução**: o engine **INCREMENTA** o rc no reclaim-setup (`ref()`), nunca
escreve valor absoluto. Portanto seed `1` ⇒ pós-reclaim `rc = 2`. Com rc=2
segurado pela própria ref do engine, o deref do teardown cai `2 → 1`,
**nunca 0** ⇒ `~CSSFontFace` não pode rodar (RefCounted.h:129-144 e
:187-192 — delete somente quando `m_refCount − 1 == 0`) ⇒ o killer rank-D
(`~HashTable` → `deallocateTable(T dangling)` → `free(T−16)`,
HashTable.h:420-428/:1163-1170) fica neutralizado **sem nenhum write
pós-spray** — lei 6 (p670/p671/p672: qualquer write LATE mata pré-R1)
intacta por construção.

## Design (`probes/phase13_webkit/p674-rcseed.html`)

Base p669-clamp exata (keepspray `__sprayAlive`, beacons batch, OBS
read-only — leituras seguras, p669; ROUNDS=8) com dois deltas:
1. **Seed**: `+0x00 = 1`, `+0x04 = 0`, `+0x44 = float 100+r+i·0.001`
   (layout /size benigno — +0x08 variant = 0 provado 9/9 no p668).
2. **Clamp LATE removido por completo** (nenhum write pós-spray — lei 6;
   justificado no header do arquivo).

Assinatura esperada: R0 hit com **rc=2** (seed 1 + engine +1); OBS com
rc=2 constante = nenhum deref intermediário (destrutor bloqueado);
rc=1 aparecendo = um deref aconteceu; rc=0 = morte iminente.

## Risco residual (honesto)

Se o `Ref protect` do `CSSFontFaceSet::remove` rodar **duas vezes** na face
forjada entre rodadas, rc 2→1→0 = destrutor dispara mesmo assim. Contra-
evidência desta noite: /size mostrou rc constante 1 através de r0/r1 (nenhum
deref intermediário observado) ⇒ provavelmente deref único no teardown
final. **Se a morte voltar no R2 ⇒ seed rc=3 (p674b), mesmo padrão.**

## Árvore de decisão

```
6 cargas de /p674 (= raiz):
(a) ALIVE end-r8-rcseed (SUMMARY + ALIVE)
    => STABLE FORGE COMPLETE — vetor WebKit 10/10. Próximo: design do
       read-primitive sobre o host estável (leituras T-relativas dentro do
       objeto forjado estável por 8 rodadas).
(b) morte no R2 (com R0 rc=2 lido e OBS rc 2->1 no meio)
    => double-deref confirmado ⇒ p674b com seed rc=3 (mesmo arquivo, +0x00
       = 3). Cada degrau de rc compra uma rodada a mais se os derefs forem
       1/rodada — medir quantas rodadas cada +1 compra.
(c) morte pré-R1 (fenótipo p670-p672 SEM write nosso)
    => seed +0x00=1 letal nesta geração — contradiz o incremento 100→101
       de p663-667 (talvez rc>1 no add-time muda um branch do engine, ex.:
       caminho adopt checando refCount) ⇒ investigar dump completo antes
       de qualquer p674b; fallback = p669/p673 como bases.
```

## Ordem de execução desta noite

1. `/p674` (raiz) — 6 cargas × ≥32 s — **a tentativa do 10/10**.
2. `/p673` — 6 cargas × ≥32 s — dataset groom (lanes/T entre rodadas;
   morte R2 esperada — o datum é o mapa pré-morte). Rodar DEPOIS do p674
   (p674 decide o clima; p673 coleta independente do outcome).

## Situação do servidor

Rotas: `/` e `/p674` → p674-rcseed; `/p673` → p673-groom; `/p672 /p671
/p670 /p669 /size /zero /skip /p666 /p667 /nosp /sp12` preservadas.
Restart realizado (serve.py + dns_hijack.py --ip 192.168.50.45) e
verificado por urllib (títulos + portas 443/53).

---

# SESSION 2026-11-11 EVENING — APÊNDICE (22:00, push final)

(Resumo da sessão original em `SESSION_2026-11-11_EVENING.md`; este
apêndice registra o turno extendido.)

## Caminhada da árvore de decisão p664 → p672 (consolidada)

| Probe | Hipótese | Veredito |
|---|---|---|
| p664 | display:swap desarma timer ⇒ sobrevive | Timer refutado (nunca arma no fluxo local()); morte R1 igual ao auto |
| p665 | S-beacons localizam morte | Morte ~150ms pós-write; R1 MISS estrutural (paridade), NÃO interferência XHR |
| p666 | batch forensics + variantes por rota | #sp24 morte R1 9/9; #nosp sobrevive R0+R1 ⇒ writes stale inofensivos; spray adianta morte 1 rodada |
| p667 | keepspray salva | Hipótese freed-backing-store MORTA — morte idêntica |
| p668 | forge benigno | **BREAKTHROUGH /size 9/9: R1 escapou** (rc=1 = engine re-ref provado); +0x08 lane-id era o killer R1 histórico |
| p669 | clamp opCount | Cleanup MORTO — opc=0 sempre; engine escreve no objeto 1x apenas (T/W/rc no reclaim-setup) |
| p670 | nulltable | Tabela DUAL-USE — nullar mata MAIS CEDO (pré-R1 9/9); nunca nullar +0x58 |
| p671 | rc=0x7FFFFFF0 | Morte pré-R1 — otimista vs pessimista em aberto |
| p672 | rc=2 sweep | **Lei 6: QUALQUER write LATE mata pré-R1** (9/9) — p669 = melhor base; 6ª âncora cb0d0 |

## Leis (numeradas)

1. Paridade: rodadas pares hitam, ímpares missam.
2. Faces precisam ficar vivas (`__facesAlive`).
3. Âncoras T de 1ª geração: `0x10001cb170 / be90 / cb8f0 / ca9a0 / cb0d0`
   (span ~0x960); estáveis dentro da geração entre cargas.
4. Engine escreve no forjado exatamente 1x (reclaim-setup): +0x58 T,
   +0x68 W, +0x00 rc (INCREMENTO +1, nunca absoluto).
5. Writes stale em memória freed-não-reusada: inofensivos ≥2 rodadas.
6. Qualquer write no lane hit na janela LATE (+3500..+3900) = morte pré-R1.
7. Killer R2 = ~HashTable sobre T dangling (rank D); único bloqueio conhecido
   = rc nunca chegar a 0 ⇒ **spray-time seed (p674)**.

## Frentes para a próxima sessão

1. **p674/p674b** — stable forge (rc seed 1→2, fallback 3); meta `ALIVE
   end-r8` = vetor 10/10.
2. **p673** — groom-series/self-address (dataset de lanes/T entre rodadas)
   para o fake-table p675.
3. **p675** — fake-table (bloqueado até self-address; ver P668_NOTES /skip
   para a análise de free(P−16)).
