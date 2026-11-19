# P668 NOTES — benign-forge variants (2026-11-11 20:58)

## Evidence recap that motivated p668

- **p667 keepspray** (`beacons_98f166b5`): 13 loads; R0 `hit=2` com âncoras T
  `0x10008a8010` / `0x10008b0010` / **`0x10001cb8f0`** (terceira âncora de
  primeira geração — banda `0x10001cb170..0x10001cb8f0`, span 0x880), rc=101,
  R0LATE vivo, e **nenhum** beacon R1 em 13/13 — morte idêntica à janela R1 do
  p666 sp24. Manter os buffers vivos (`__sprayAlive`) não mudou NADA:
  **hipótese backing-store-libertado está MORTA** (linha 3 da árvore p667,
  sob a interpretação "reclaim-fresh-per-round é letal por si").
- **nosp (p666)**: sobrevive R0+R1 com o slot forjado contendo os dados ANTIGOS
  VÁLIDOS do objeto (harmless); spray morre com NOSSOS SEEDS no slot.
  Delta controlado = conteúdo dos bytes do slot.

## Fonte da análise: quem toca uma CSSFontFace de load ANTERIOR quando
`document.fonts.load()` roda de novo (família diferente)?

Chamada de nível superior: `FontFaceSet::load()` — `FontFaceSet.cpp:153-214`
(= `tools/.wk-reference/Source/WebCore/css/FontFaceSet.cpp`):

1. `m_backing->updateStyleIfNeeded()` (:155) → `CSSFontFaceSet::updateStyleIfNeeded`
   → `CSSFontSelector::updateStyleIfNeeded` (CSSFontFaceSet.cpp:106-110) —
   re-parse de `@font-face` se o stylesheet mudou; cria faces NOVAS, não toca
   as antigas (exceto via `add`/`remove` — ver abaixo).
2. `matchingFacesExcludingPreinstalledFonts(font, text)` (:156) →
   `CSSFontFaceSet::matchingFacesExcludingPreinstalledFonts` —
   `CSSFontFaceSet.cpp:385-431`: para cada codepoint do texto 'AB', para cada
   família no shorthand (`f1`, `s1`), `fontFace(request, family)` (:449-521):
   - `m_facesLookupTable.find(family)` (:450) — hash map por família. Round 2
     consulta `f1`/`s1`, NÃO `f0`/`s0`: o iterador do lookup table não passa
     pelas faces antigas por aqui.
   - `m_cache` por família+request (:455-458): `CSSSegmentedFontFace::create()`
     e o loop de candidatos (:464-479) **itera `familyFontFaces`** (Vector<Ref<CSSFontFace>>)
     chamando `candidate.status()` (:466) e
     `candidate.fontSelectionCapabilities()` (:467/:477/:487) — MAS só para a
     família pedida. A face antiga só entra aqui se a família dela for
     consultada — não é o caso (famílias únicas por rodada).
   - `std::stable_sort` + `appendFontFace` (:492-518): idem, só candidatos da
     família corrente.
   - `matchingFaces` itera `faces->constituentFaces()` chamando
     `constituentFace->isLocalFallback()` e `->rangesMatchCodePoint()` (:414-417)
     — `rangesMatchCodePoint` lê `m_ranges` (Vector @ ~+0x30, deref se
     non-empty). Só faces da família corrente.
3. `face.get().load()` (:169) → `CSSFontFace::load()` → `pump(Allow)`
   (CSSFontFace.cpp:643-699) — opera em `this` (face NOVA); o loop de fontes
   antigas não passa aqui.
4. `pendingPromise->faces.append(face.get().wrapper(scriptExecutionContext()))`
   (:207) → `CSSFontFace::wrapper()` — CSSFontFace.cpp:518-528: lê `m_wrapper`
   (+0x68); se null, cria wrapper. `initializeWrapper()` lê `m_status` (+0x82)
   e chama `fontStateChanged` no wrapper novo. Só faces correntes.
5. `m_pendingPromises.add(face.get().existingWrapper(), ...)` (:210) — lê
   `m_wrapper` (+0x68). Só correntes.
6. `document.fonts.delete(ff)` do getter (rodada ANTERIOR) já removeu a face
   antiga de `m_faces`/`m_facesLookupTable` (CSSFontFaceSet::remove :250-281)
   — mas `remove` chama `face.families()` (CSSFontFace.cpp:412-415 →
   `m_families` +0x18 deref via `properties()`/`switchOn` de
   `m_propertiesOrCSSConnection` +0x08!) e `face.cssConnection()` (:260-262 →
   `switchOn` +0x08 deref) e `m_faces[i]->removeClient(*this)` (:271 →
   HashTable remove em `m_clients` +0x58 table deref + rehash interno).
   **Esse é o caminho que deref +0x08 e +0x58 da face ANTIGA** — mas roda no
   PRÓPRIO round do delete (dentro do getter), não no round 2.

Onde mora a Ref que mantém rc=101: `m_faces` é `Vector<Ref<CSSFontFace>>`
(remove libera); `m_pendingPromises` é keyed por WRAPPER
(FontFaceSet.cpp:210), e `pendingPromise->faces` também seguram WRAPPERS
(RefPtr<FontFace>), cujo `m_backing` é `Ref<CSSFontFace>` (FontFace.cpp:165-171)
→ **enquanto o wrapper `ff_r` viver (`__facesAlive`), a Ref backing vive —
essa é a Ref que mantém rc=101**, mesmo após `fonts.delete`. O
`document.style` removido derruba a conexão CSS, mas o wrapper JS segura a
face. rc=101 é exatamente seed(100)+1: a Ref do wrapper. **Corolário
crítico**: o objeto "libertado" cujo slot reclaimamos NÃO é a face do
wrapper — é a face conectada ao CSS (`s0`), cujo dono era o stylesheet
removido; o engine escreve nela até o estilo ser re-avaliado (updateStyleIfNeeded
do round seguinte = momento da morte).

Iteração exata que roda no round 2 e toca a face antiga:
`FontFaceSet::load()` round 2 → `updateStyleIfNeeded()` (FontFaceSet.cpp:155)
→ re-style com o stylesheet antigo removido → `CSSFontSelector` desmonta as
regras `@font-face` órfãs: `CSSFontFaceSet::remove(face-antiga)` (remove do
vector durante a atualização de estilo) → `face.families()`
(CSSFontFace.cpp:412 → `properties()` :111-121 → **switchOn deref de
`m_propertiesOrCSSConnection` +0x08**) e `removeFromFacesLookupTable` (itera
`families` deref +0x18), `cssConnection()` (:138-141, +0x08 deref), e
`removeClient` (HashTable +0x58). **Se +0x08 contiver nosso lane-id (int 2),
`switchOn` trata 2 como ponteiro/discriminante → deref de 0x2 → crash.** Com
buffer ZERO: `Ref<MutableStyleProperties>` nulo — `switchOn` em variant
monostate-index-0 = `MutableStyleProperties` alternativo com ponteiro null:
`properties()` retorna `Ref` de null (UB no deref :115/:123, mas flag de
layout não é lida antes do deref do ponteiro — crash provável também, ver
oráculo /zero).

## Tabela suspeitos (rank)

| Rank | Campo (offset) | Leitura/deref em | Seed antigo | Crash esperado |
|---|---|---|---|---|
| 1 | `m_propertiesOrCSSConnection` (+0x08) | `properties()` CSSFontFace.cpp:111-121; `cssConnection()` :138-141; `mutableProperties()` :125-133; via `families()` :412; via `remove` CSSFontFaceSet.cpp:260-262; via `addToFacesLookupTable` :169 | lane-id int pequeno (2) | deref de 0x2 — crash SEGURO |
| 2 | `m_families` (+0x18, RefPtr) | `families()` CSSFontFace.cpp:412-415; `addToFacesLookupTable` CSSFontFaceSet.cpp:170-188 (itera a CSSValueList); `removeFromFacesLookupTable` :225-247 | 0 (zerado) | deref null em `*families` :171/`face.families()` — crash se null não checado (`if (!families) return` :171-175 checa!) → **null-safe** |
| 3 | `m_clients` (+0x58 table, +0x60 opCount) | `removeClient` CSSFontFace.cpp:487-492 (HashTable remove → m_table deref, metadata em m_table[-1..-4]); `addClient` :484-485; `iterateClients` :57-61 (copyToVectorOf<Ref<Client>> — deref de cada entry + RefCounted ref()) | 0 → depois T (engine) | table null → HashTable::remove deref null → crash possível; com T real = aliasing benigno (itera clientes REAIS) |
| 4 | `m_wrapper` (+0x68) | `existingWrapper()` CSSFontFace.cpp:163-166; `wrapper()` :518-528; `document()` :464-469 | 0 | null-checked (`if (m_wrapper)`) → benigno |
| 5 | `m_status` (+0x82 u8) | `status()` :572 (via switch :573-588 setStatus ASSERTs desligados NDEBUG); `fontStateChanged` FontFace.cpp:332-352; `initializeWrapper` :495-509 | 0 (Pending) | Pending=0: `setStatus(Loading)` ASSERT apenas; iteração `check()` CSSFontFaceSet.cpp:440-445 lê status — valor 0 é válido (Pending) → benigno |
| 6 | `m_sources` (+0x48 Vector) | `pump` CSSFontFace.cpp:649-699 (itera sources, `source->status()`, `source->load()` deref); `computeFailureState` :472-479 | 0 | Vector nulo (buffer 0) = vazio: loops não executam → benigno SE m_data null; capacity/size 0 = ok |
| 7 | `m_timeoutTimer` vptr (+0x90) | `setStatus` → `m_timeoutTimer.startOneShot/stop` CSSFontFace.cpp:611-625 → **vcall no vptr** | 0 | vcall em vptr null → crash SE atingido; só ocorre via setStatus(Loaded/Success/Failure) na face antiga — não roda neste fluxo local() (timer arma-para-no-pump síncrono; ver P666_DESIGN §2) |

## Variantes construídas

| Rota | Arquivo | Seeds | Papel |
|---|---|---|---|
| `/zero` (raiz) | `p668v-zero.html` | NENHUM (buffer zerado) | Host "objeto vazio": se R1 escapa, conteúdo era o assassino (mais provável +0x08) e forge zero = leak multi-rodada benigno → WIN |
| `/size` | `p668v-size.html` | float @ +0x44 (`m_sizeAdjust`) = 100+round+i*0.001 | Marcador benigno (dado puro, nunca dereferenciado: `CSSFontFace.cpp:333-336`, `:749`); se sobrevive COM hit, marcador + engine-write coexistem → leak read-only multi-rodada com round/lane codificável |
| `/skip` | `p668v-skip.html` | +0x58/+0x5C = 0 explícito (resto zero), ROUNDS=4 | Oráculo null-table: forge de "skip" completo é impossível pré-leak (metadados da HashTable moram em m_table[-1..-4], fora do lane; m_table auto-referencial exigiria o VA do lane — o gap central). Testa se algo deref m_table antes do engine re-estampar T. Se morrer igual a p667 → sem sinal extra (só consistência) |

## Árvore de decisão

```
/zero (10 cargas):
├─ R1 escapa (beacon R1 presente)
│   ├─ R1 HIT ....... conteúdo era o assassino; forge-zero = host multi-rodada.
│   │                 -> p669: reaparecer campo a campo (+0x08 primeiro) até
│   │                    achar o byte letal; depois forjar +0x08 = Ref nula
│   │                    VÁLIDA (variant monostate) e medir quantas rodadas
│   │                    sobrevivem com leak T/W/rc.
│   └─ R1 MISS ...... sobreviveu mas sem reclaim na rodada 1: groom p669
│                     (pré-alocar 192B antes do round 1 para vencer a loteria).
└─ R1 NUNCA escapa (morre igual p667)
    └─ assassino é estrutural (write-target do engine/iteração), não nossos
       bytes -> /skip diz qual: morrer igual = m_table null não é (única)
       deref letal; sobreviver = tinha deref pré-write em m_table.
/size (6 cargas): espelha /zero; hit+vivo = marcador benigno confirmado.
/skip (4 cargas): oráculo apenas.
```

## Protocolo de execução

1. serve.py restartado (rotas: `/` e `/zero` → p668v-zero; `/size`;
   `/skip`; `/p667`, `/nosp`, `/sp12`, `/p666` preservadas).
2. **10 cargas de `https://192.168.50.45/`** (= /zero, ROUNDS=8, ~32 s por
   carga — aguardar antes de recarregar).
3. 6 cargas de `https://192.168.50.45/size`.
4. 4 cargas de `https://192.168.50.45/skip`.
5. Grep: `P668Z-R1` / `P668T-R1` / `P668S-R1` (a presença do beacon R1 é a
   vitória), `SUMMARY`/`ALIVE end-r8`, e última posição por carga.
