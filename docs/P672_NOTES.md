# P672 NOTES — rc-sweep (2026-11-11 21:50)

## A tabela do quebra-cabeça (três probes, uma variável cada)

| Probe | Intervenção no LATE | Resultado |
|---|---|---|
| p669 | nenhuma | **R1 passa** (beacon dispara), R1LATE vivo, morte R2 |
| p670 | `m_table = 0` (+0x58/+0x5C) | **morte PRÉ-R1** |
| p671 | `rc = 0x7FFFFFF0` (+0x00) | **morte PRÉ-R1** (log `beacons_d6d8c262`: ~12 cargas, 9 limpas: R0 hit → R0LATE → `RCINF r0 rcwas=1` → silêncio) |

Ambas as intervenções **adiantaram** a morte.

## Análise honesta da janela temporal (+3500 .. +3900 ms do round 0)

- +3500: R0LATE + RCINF (nosso write no lane)
- +3750: `beginRound` do round 1 — **style insert, FontFace construct,
  `fonts.add`, `void ff.loaded`, `fonts.load` trigger**
- +3900: analyzeEarly do R1 (o beacon que p670/p671 nunca emitiram)

p670/p671 morreram entre +3500 e +3900 ⇒ **dentro da maquinaria de fontes do
beginRound** — o primeiro código do engine a tocar o FontFaceSet após o
nosso write. No p669 (sem write) o mesmo beginRound passou ilesso ⇒ não é o
beginRound em si que mata; é a interação dele com o buffer modificado.

## Source hunt — quem lê rc no caminho add/load/teardown (citações)

| Leitura | Onde | Veredito |
|---|---|---|
| `hasOneRef()` | `FontFaceSet.cpp:251` — `if (pendingPromise->hasOneRef())` | **É no PendingPromise, NÃO na face** — não lê nosso +0x00 |
| `purgeable()` | `CSSFontFace.cpp:762-764` — `return cssConnection() && m_mayBePurged;` | **NÃO lê refCount** — só variant (cssConnection) + flag bool |
| `m_mayBePurged` set | CSSFontFace.cpp:101 (`!wrapper` no ctor) e :515 (`false` em initializeWrapper) | A face CSS-conectada sem wrapper fica purgeable=true — mas `purge()` (CSSFontFaceSet.cpp:287-296) só roda em `buildStarted` e itera `m_faces` — a face forjada JÁ SAIU de m_faces no getter do round 0 (fonts.delete + teardown) |
| Remoção no build | `CSSFontSelector::buildStarted` :130-147 (coleta `cssConnectionsPossiblyToRemove`) / `buildCompleted` :149-168 (`m_cssFontFaceSet->remove(*face)`) | `CSSFontFaceSet::remove` :250-281 faz `Ref protect { face }` (ref/deref) — mas só em faces AINDA em m_faces |
| ref()/deref() na face | CSSFontFaceSet::add :210 (`m_faces.append(face)` = Ref), remove :271 loop | ref/deref de manutenção do vetor; **nenhum branch dependente do valor** do rc fora do 1→0 |

**Conclusão da caça**: NENHUM caminho add/load lê `refCount()`/`hasOneRef()`
da CSSFontFace. O leitor exato do rc (ou da tabela) na janela +3500..+3900
**não é identificável estaticamente** — candidatos residuais: (i) a própria
`Ref protect` do remove/adopt fazendo `deref()` no buffer com rc gigante
(deveria ser benigno: nunca chega a 0); (ii) race: nosso write colide com um
reader/writer engine em microtask do fim do round 0; (iii) caminho PS5-only
(forque Sony) não presente no clone 616.1.27. O sweep empírico é o
discriminador correto.

## p672 — rc = 2 (`probes/phase13_webkit/p672-rcsweep.html`)

Base p671 exata; RCINF agora escreve **rc = 2** (u32 @+0x00, +0x04 = 0) na
LATE de cada rodada em todo lane hit, com **re-arme**: se um RCINF posterior
emite `rcwas=<v>` diferente de 2, o engine escreveu através do nosso buffer
(ref ou deref) e a emissão revela a direção (2→3 = ref; 2→1 = deref) —
experimento natural embutido.

**Racional do rc=2**: bloqueia o destrutor (deref 2→1, nunca 0 —
RefCounted.h:129-144) mantendo a face na condição "segura por 2 refs" —
estado de vida normal para qualquer objeto com wrapper + coleção, sem
fast-path anômalo que um rc gigante poderia desencadear.

## Árvore de decisão

```
6 cargas de /p672 (= raiz):
(a) beacon R1 escapa (+ possivelmente mais)
    => LEITURA OTIMISTA confirmada: rc é ponto de controle vivo; o valor
       importa. Sweep rc=3/4 nas próximas sessões; alvo end-r8 com valor
       afinado. Os RCINF re-armados mapeiam refs/derefs do engine por rodada.
(b) morte PRÉ-R1 de novo (fenótipo p670/p671)
    => LEITURA PESSIMISTA: QUALQUER write no lane na janela LATE mata —
       valor irrelevante (race/leitor não-staticamente-identificável).
       Pivot: mover a intervenção para o EARLY (+150ms, logo após o write
       do engine aterrissar, antes de qualquer teardown) OU aceitar p669
       como melhor base e ir para substep beacons do R2 (padrão p665).
(c) fenótipo NOVO (morte no analyze do R1 ou R1.5)
    => rc=2 parcial: o bloqueio do destrutor ajudou mas outra coisa engata
       no meio da rodada — cruzar com OBS (rc drift) para separar
       ref-vs-deref.
```

## Protocolo

1. serve.py restartado; `/` e `/p672` servem p672-rcsweep; `/p671 /p670
   /p669 /size /zero /skip /p666 /p667 /nosp /sp12` preservados.
2. **6 cargas de `https://192.168.50.45/`** — **≥32 s por carga** antes de
   recarregar.
3. Grep: `P672-R1` (**a vitória mínima: o beacon R1 escapar**),
   `P672-RCINF` (rcwas=1 na primeira; re-emissões = drift do engine),
   `P672-OBS` (rc ao longo dos rounds), `ALIVE end-r8-rcsweep2` (vitória
   total), posição do último beacon por carga.
