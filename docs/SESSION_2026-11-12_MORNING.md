# SESSÃO 2026-11-12 MANHÃ — Fechamento Multi-Hit, W-Vector, Gadget Hunt
Período: 08:41–09:36 | Probes: p678, p678b, p679, p680, p681, p682, p683, p684, p685

## §1 Resultado-chave da sessão (EVIDÊNCIA p685, 09:34:14)

PRIMEIRA COEXISTÊNCIA CAMPO-NOSSO + WRITES-ENGINE no dump do forjado:
  R0DUMP1 0:0000000000000001(engine rc), 8:00000010007e4c80(NOSSO variant seed),
  40:42c8000000000000(nosso float), 58:...T(engine), 68:...W(engine)
Significado: controlamos um ponteiro de 64 bits que o engine LÊ no teardown
(CSSFontFaceSet::remove -> cssConnection() -> switchOn do variant @+0x08) sem
crash imediato (miss do lookup foi no-op benigno). Fundação do deref-gadget
comprovada em device. Hit migrou p/ lane 0 (novo dado: lane não é fixa).

## §2 Fechamento do espaço multi-hit (por refutação completa)
| Hipótese | Probe | Veredito |
|---|---|---|
| névoa estática sufoca reclaim | p679 corredor duplo | MORTA (R2 janela morta/miss) |
| corredor errado | p680 dinâmico 5r | MORTA (R2-R7 MISS, vivo) |
| keepspray engargala freelist | p681 partial-keep | MORTA (R1/R2 MISS) |
Conclusão estrutural: reclaim-setup acontece UMA vez por carregamento; rounds
seguintes nunca são carimbados. Multi-hit por carga é matematicamente bloqueado.

## §3 Regressão T×lane (refutação com dados)
107 hits, 11 logs: T=0x10001ca9a0 visto com lane 1 (88x) E lane 4 (19x) —
mesmo T, lanes diferentes => T não é função da lane (T = m_clients table,
alocação separada). Self-address via T×lane: MORTO.
MAS: T por geração tem passos DISCRETOS de 0x4000 (16KB) — mapa de páginas.

## §4 W-vector (p682) — a âncora da sessão
W = WeakPtrImpl (ilha 0x10007e6xxx, span 0x3F0, quase estável POR SESSÃO).
p685: persistência W entre cargas via localStorage funcionou (wprev=10007e4c80
-> usado na geração seguinte; ilha deslocou só 0x880). W é a âncora mais
estável já medida. FontFace vivo contém m_backing (Ref<CSSFontFace>) = ponteiro
para face irmã viva — o alvo do futuro read.

## §5 Gadget hunt (P683_GADGET_ANALYSIS.md) — status
| # | Gadget | Status |
|---|---|---|
| 3 | timer->m_function() call | MORTO (p683 data: gf=-1 getter não dispara; p683 híbrido: forge ok mas st82=0 sempre; p684 woff2 válida servida: st82=0 persiste — forjado nunca entra no ciclo de load) |
| 1 | remove->cssConnection (+0x08) | VIVO — premissa comprovada (§1) |
| 2 | pump->sources vcall | fraco (precisa VA) |

## §6 Infra da manhã
- woff2 válida mínima (292B, fontTools+brotli) servida em /f.woff2
- rotas novas: /p678 /p678b /p679 /p680 /p681 /p682 /p683 /p684 /p685 /f.woff2
- correções: h10 START tag; layout_probe nota vptr (fork Sony sem vptr, 192B)
- lições de engenharia: node --check antes de todo deploy (p683-branco);
  W_PREV hoisting; escape de aspas em CSS replace; UTF-8 enforcement

## §7 Próximo passo definido (heap-oracle)
Semear variant @+0x08 com ENDEREÇOS CANDIDATOS (varredura da banda T em passos
0x4000; e W-region) em cargas sucessivas; usar hit/miss/sobrevivência como
oráculo binário de "este endereço contém X?" — read-primitivo por 1 bit/carga,
escalável com múltiplos seeds por carga (lanes 0-4 = 5 perguntas/carga).

## Placar
WebKit vector 9.5/10 (gadget #1 fundação provada; read-primitive = último elo)
Kernel R/W 0/15 | Aggregate ~75.5/100