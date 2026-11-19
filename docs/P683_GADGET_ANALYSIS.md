# P683 — Análise de Gadgets de Deref (read-primitive)
Data: 2026-11-12 09:10 | Fonte: clone 616.1.27 (Sony fork sem vptr, objeto 192B device-validado)

## Contexto device (leis validadas)
- Forge em lane 192B; engine escreve SÓ +0x58(T)/+0x68(W)/+0x00(rc++) no reclaim-setup
- Lei 6: sem writes pós-reclaim (página morre); seeds só no spray-time
- Campos spray-time vivos: +0x08 variant, +0x18 m_families, +0x48 m_sources, +0x82 m_status, +0x44 float
- Heap: T banda 16KB-step; W ilha 0x10007e6xxx span 0x3F0 (quase eterna); lanes banda 0x10001c-0x10008a

## Candidatos (ranked)

### #1 — REMOVE-PATH via variant +0x08 (PROVADO rodar: era o killer pré-R1)
Cadeia: teardown R1 → CSSFontFaceSet::remove(face) (CSSFontFaceSet.cpp:250) →
  face.families() → m_families (+0x18, RefPtr null-checked = benigno com 0)
  MAS remove() também chama cssConnection() → switchOn(m_propertiesOrCSSConnection @+0x08)
  → variant alternativa StyleRuleFontFace* → m_constituentCSSConnections.remove(ptr)
  → HashTable.remove(ptr) na tabela DO SET (viva!) com chave = NOSSO ponteiro seed
Oracle: remove() em m_constituentCSSConnections (HashSet<StyleRuleFontFace*→face>) procura
  o ponteiro que SEMEARMOS em +0x08. Se semearmos um ponteiro REAL conhecido (ex: W!),
  o lookup lê m_constituentCSSConnections[hash(W)] — tabela viva do set — e o RESULTADO
  (hit/miss) decide se remove() roda o branch que deref o valor.
  SIDE-CHANNEL: se W (conhecido, 0x10007e6xxx) estiver no bucket, o engine remove a entry
  e escreve tombstone na tabela do SET — observável como mudança de comportamento?
  MELHOR: semear +0x08 = endereço DENTRO DO PRÓPRIO LANE não dá (não sabemos VA).
  Semear +0x08 = W → cssConnection() retorna W como StyleRuleFontFace* → remove(W) na
  tabela do set → hash lookup com ponteiro REAL → MISS provável (W não é StyleRule) →
  remove() no-op → teardown CONTINUA sem deref de W. Se MISS é benigno, o probe sobrevive
  e PROVA que controlamos o branch. Não é read ainda — é o gadget de CONTROL confirmável.

### #2 — PUMP via m_sources +0x48 (font()/load() da rodada N)
Cadeia: fonts.load() → face.load() → pump() (CSSFontFace.cpp:644) → m_sources.size()
  (Vector @+0x48: m_buffer ptr + m_capacityAndSize) → se size>0: m_sources[i]->status()
  = DEREF DE m_sources[i] (unique_ptr, ponteiro que SEMEAMOS) → vcall CSSFontFaceSource::status()
  = VCALL COM VTABLE CONTROLADA (se apontarmos p/ dentro do lane... precisa VA. DEAD law-6? NÃO:
  o ponteiro é seed-time! mas apontar pra ONDE? sem self-address, só endereços conhecidos:
  W (ilha estável!). m_sources[0] = W → engine deref W como CSSFontFaceSource → lê vtable
  em *(W) = conteúdo REAL do WeakPtrImpl block → VCALL em função real = crash provável,
  MAS o CRASH ADDRESS revela *(W) — oráculo de crash-dump não disponível no PS5 browser.
  VEREDITO: precisa de heap-spray de vtable fake em endereço conhecido — W é conhecido mas
  não controlável. DEAD até termos escrita em W-region.

### #3 — TIMEOUT TIMER +0x90 (display:auto + font remota)
Cadeia: setStatus(Loading) com block 3s → m_timeoutTimer.startOneShot → ~3s → fired()
  → Timer::fired é NON-virtual em TimerBase? (Timer.cpp: fired() = m_function() —
  Function<void()> @+0x90+0x28 aprox = PONTEIRO QUE SEMEAMOS (spray-time!) →
  CHAMADA DIRETA DE PONTEIRO CONTROLADO = PC CONTROL PRIMITIVE.
  Sony-sem-vptr arithmetic: timer = {2×double fire/repeat, RefPtr heapItem, Ref thread,
  Function impl-ptr + inline} = 8+8+8+8+8(+8) — precisa bater 192-0x90=96B... 0x90=144;
  192-144=48B de timer. {2d=16, heapItem=8, thread=8, function=8, inline=8} = 48 EXATO!
  Function = impl-ptr(8) + inline buf(8) = 16B NO Sony (não 8!) → bate 48.
  m_function impl-ptr em +0x90+32=+0xB0 — DENTRO DO LANE (< 192). SEED CONTROLADO!
  PROBLEMA: local() fonts = timer arma-e-para síncrono (nunca dispara). PRECISA de fonte
  REMOTA (src:url) que mantenha status=Loading — nosso probe usa local(Arial).
  VEREDITO: VIÁVEL com src:url(data:...font) + display:block/auto! timer 3s dispara →
  chama *(seed em +0xB0) → PC control no LLInt. É o candidate MAIS FORTE — é não só read,
  é RCE-direto. Teste: p683 seed +0xB0 = endereço de função REAL conhecida (precisa leak
  de text-base... não temos!). Sem base: seed +0xB0 = W+8 (ilha) → o que estiver lá vira
  PC — WeakPtrImpl block contém ponteiros reais → call em ptr real = crash revelador via
  comportamento (crash x sobrevive). ORÁCLE BINÁRIO: chamar W+delta = endereço de
  WeakPtrImpl vtable-ish → se vira algo executável, página morre COM assinatura
  diferente (timing do crash: t≈3.3s pós-load = PROVA do timer path).
  PRÓXIMO PASSO HONESTO: primeiro só PROVAR QUE O TIMER DISPARA (seed +0xB0=0 →
  crash em t=3.3s com página que sobreviveu até lá = oráculo de tempo!). Isso é o p683.

## Aritmética 192B Sony (sem vptr)
0x00 rc(4)+pad | 0x08 variant(16) | 0x18 families(8) | 0x20 ranges(16) | 0x30 features(16)
0x40 behavior(1)+pad+sizeAdjust(4) | 0x48 sources(16) | 0x58 clients(16) | 0x68 wrapper(8)
0x70 caps(18)+status/bools(6) | 0x80 pad(8)... wait 0x82 status — 0x80..0x81 pad do caps
0x88 bools(2)+pad | 0x90 timer(48): fire(8)+repeat(8)+heapItem(8)+thread(8)+funcImpl(8)+inline(8)
Total: 0x90+48 = 144+48 = 192 ✓ EXATO — bate com o lane.

## Tabela resumo
| # | Gadget | Campo seed | Oracle | Lei6 | Status |
|---|--------|-----------|--------|------|--------|
| 1 | remove→cssConnection→set-table-remove | +0x08=W | branch control (sobrevive?) | OK | testável já |
| 2 | pump→sources[0]->status() vcall | +0x48=W | crash address (sem dump) | OK | fraco sem VA |
| 3 | timer 3s→m_function() call | +0xB0=0/W | CRASH @ t=3.3s (oráculo TEMPO) | OK | **TOP: p683** |

## p683 — especificação (timer-fire oracle)
Base: p669 (/size seeds) COM delta:
1. FontFace com src:url(data:font/woff2;base64,...) — carregamento ASSÍNCRONO
   (data: URL resolve rápido mas via path async → status fica Loading um turn)
   + display:auto (block 3s) via opção display.
2. Seed +0xB0 (u64) = 0 no target lane (e 0 nos demais — zero default).
3. PREVISÃO: se timer dispara no forjado → call(null) → crash em t≈load+3.0-3.4s.
   Beacon 'ALIVE-at-3.5s' do R0LATE (já existe) = timer NÃO disparou (local-path);
   morte ENTRE R0LATE(+3.35s) e R1analyze = timer DISPAROU = gadget CONFIRMADO.
4. Árvore: (a) morte ~3.3s pós-trigger = timer-fire no forjado CONFIRMADO → p684 =
   seed +0xB0=W+delta (call em conteúdo real — endereço de código?) → leak por comportamento;
   (b) sobrevive = timer não alcança o forjado (para antes) → candidato morto → #1;
   (c) morte noutra janela = outro mecanismo → revisitar.
Notas: data-URL precisa ser fonte VÁLIDA mínima (senão Failure imediato). Gerar woff2
   mínimo de 1 glifo no build (base64 fixa). Se data: resolver sync como local, tentar
   url(https://192.168.50.45/font.woff2) do próprio server (rede local = rápido, async).