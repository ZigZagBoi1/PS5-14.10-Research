# Análise de ponteiros, FreeBSD e novos vetores — 17/10/2026

## Conclusão operacional

A auditoria de 168 logs encontrou 136 ocorrências que passam pelo teste ingênuo `high_dword >= 0xffff8000`, mas nenhuma é um ponteiro de kernel confirmado. As ocorrências se dividem em quatro grupos: sentinelas `0xffffffff_*`, endereços artificiais usados em varreduras, valores de dispositivo/GPU e endereços de userland sign-extended. O único padrão que merece uma nova medição é o valor escalar do syscall 624; ele muda entre conexões e deve ser tratado como possível contador de VM ou recurso, não como leak de KASLR.

Foram adicionadas três sondas novas, sem execução automática no alvo: `53a_pointer_pattern_matrix.lua`, `53b_624_oracle_deep.lua` e `53c_sony_unreferenced_lowrisk.lua`. Elas estão em `probes/phase13_52batch/` e têm como objetivo medir, classificar e delimitar resultados, não tentar escrita no kernel, execução nativa ou alteração persistente de estado.

## Padrões que pareciam ponteiros, mas não são

O falso positivo mais comum é `0xffffffff00000000` ou `0xffffffffffffffff`. O dump de `kinfo_proc` já mostrou esses valores em campos que se comportam como máscaras ou sentinelas. A regra de classificação correta precisa rejeitar todo valor com `hi == 0xffffffff` antes de considerar o intervalo de kernel.

A sonda antiga `13_nwake_oracle` imprimiu uma grade de VAs sintéticos em `0xfffff800...`; esses valores são os próprios endereços de teste, não dados retornados pelo kernel. Os resultados de `41b`, `41c`, `41e` e `41h` contêm VAs de heap ou valores negativos próximos do topo do espaço de endereçamento porque o logger formata aritmética de ponteiros como inteiro de 64 bits. Eles não demonstram leitura de memória kernel.

O resultado de `17_dmem_kptr` é igualmente ambíguo: `0xffffffff2ec47fc0` e os padrões `0xffffffff80000000`/`0xffffffff80200000` aparecem junto com o mapeamento de `/dev/dmem0`, que o próprio projeto identificou como janela de GPU. O valor `0x80000000_c0012800` é compatível com registrador de hardware GPU, não com uma base de kernel FreeBSD.

Há ainda os valores `0xffffffff91...` de `47b`, que pertencem ao dump de objetos/CClosures e devem ser tratados como dados sign-extended ou sentinelas até que exista uma segunda observação com alinhamento, estabilidade entre conexões e relação com uma estrutura conhecida. Nenhum desses grupos satisfaz simultaneamente os três critérios mínimos de um leak: intervalo de kernel plausível, valor não-sentinela e repetição correlacionada com uma estrutura do kernel.

## Cross-reference com FreeBSD

A implementação pública de `kern_sysctl.c` mostra que sysctl expõe handlers que produzem valores por `SYSCTL_OUT`; a rota normal é uma cópia controlada para o buffer de userland. Isso é consistente com os resultados: `kern.version`, `kern.ostype`, `kern.osrelease`, `kern.boottime` e `kern.proc.pid` retornam dados, mas não preservam ponteiros internos.

A fonte `vm_meter.c` é particularmente relevante para 624. Ela registra contadores como `v_syscall`, `v_trap`, `v_vm_faults`, `v_cow_faults`, `v_free_count`, `v_active_count` e `v_inactive_count`. Alguns são lidos como contadores de 64 bits; outros são calculados sob demanda. Um syscall Sony que retorna um número pequeno, muda entre conexões e não modifica um buffer combina muito mais com uma métrica desse tipo do que com endereço virtual.

`kern_descrip.c` também reduz a expectativa para `fstat`: o caminho expõe uma representação de `struct stat`, não o `struct file` interno. Portanto, `st_ino` de socket só deve ser considerado leak se houver valor repetível em faixa de kernel e correlação com o objeto; não basta um campo grande ou não-zero. A nova 53a preenche a estrutura com canário e varre o bloco inteiro para eliminar leituras de bytes não escritos.

O caminho de entrada em `ip_input.c` valida versão, comprimento e checksum antes de chamar `ip_dooptions()`. Quando há fragmentação, chama `ip_reass()` antes da entrega ao protocolo. Isso explica por que os testes de saída/loopback não são uma prova completa sobre pacotes externos, mas também mostra que o melhor próximo passo é uma comparação de comportamento e tempo entre entrada válida e rejeição, não uma nova campanha cega de malformed packets. Os resultados existentes de 49a/49b já cobriram as classes mais óbvias sem crash.

As páginas públicas consultadas são úteis como modelo de controle de fluxo, mas não são uma confirmação exata do fork Sony `r230171`. Estruturas privadas e números Sony devem continuar sendo derivados do dump local e dos logs.

## KASLR: o que ainda vale testar

`kldstat`/`kldsym` e AF_ROUTE perderam prioridade como rotas de sucesso: os logs do projeto registram kill no kernel para os primeiros e saída sem ponteiros para AF_ROUTE em 14.10. Repeti-los sem uma diferença concreta de argumento apenas reproduz um caminho morto.

A melhor linha remanescente é uma matriz de saídas read-only com classificação de ponteiros e medidas de tamanho/tempo. Ela pode capturar um erro de scrub que os dumps esparsos perderam, mas não deve ser interpretada como exploit até aparecer um valor real `0xffff8xxx...` que seja estável e alinhado a uma estrutura.

O syscall 624 é a única anomalia com sinal informacional consistente. A 53b mede quatro relações: repetição imediata, número de páginas alocadas, liberação reversa e atraso curto. Um contador de páginas tende a responder a alocações em degraus; um contador de chamadas tende a crescer quase monotonicamente; um valor de temperatura/CPU tende a ter variação temporal e baixa correlação com heap. Essa distinção é mais promissora que sondar novas VAs kernel com `mincore`, que já retornou apenas erro.

## Revisão dos syscalls ainda não experimentados

O índice local contém 115 entradas implementadas entre 532 e 676. A busca nas sondas encontrou 46 números sem referência, incluindo 533–536, 540–546, 551, 553–558, 567, 587, 598, 602–604, 610–611, 613, 615, 619, 623, 625–627, 630, 635–636, 638–639, 641–642, 649 e 653–660. Esses números foram colocados em 53c com argumentos zero e parada no primeiro resultado anormal.

A ordem é deliberadamente conservadora. Primeiro se observa se o slot aceita chamada sem argumentos, qual retorno produz e quanto tempo consome. Só depois de sobreviver a essa etapa vale construir estruturas específicas, sempre uma por conexão. O cluster 661–675 não foi incluído, pois a sonda 51c foi encerrada no syscall 661; essa evidência é suficiente para evitar uma varredura em lote.

## Timing side-channels e leaks informacionais

Os logs atuais não provam um timing side-channel porque as medições não estão normalizadas para conexão, carga e alocações. Ainda assim, há três sinais mensuráveis:

1. O retorno de 624 varia entre conexões.
2. Alguns syscalls encerram o processo quase instantaneamente, enquanto outros retornam erro normal.
3. Operações como sysctl, fstat e chamadas Sony podem retornar comprimentos diferentes sem preencher todo o buffer.

As sondas novas imprimem `os.clock()` apenas como medida relativa dentro da mesma conexão. Isso não é um relógio de alta resolução nem uma prova de informação sobre outro processo. Para uma conclusão estatística, repetir em muitas conexões e comparar medianas, quantis e tamanho de saída é necessário; o primeiro passo deve ser medir estabilidade, não tentar inferir bits de KASLR.

## Corridas sem threading

A hipótese de usar AIO para obter concorrência deve ser marcada como morta no estado atual: o resultado de 43p mostra encerramento no kernel via `make_syscall`, portanto o bypass não removeu a barreira. `thr_new` também foi registrado como crash/kill. Sem uma segunda thread, uma corrida clássica de close/read ou timer/settime não é uma primitiva disponível.

O que ainda pode ser estudado com segurança é reentrância síncrona: handlers de sinal, callbacks de socket e timers que retornam ao userland. Mas isso só se torna prioridade se houver uma diferença observável de estado ou uma chamada que bloqueie de forma controlada. Não há evidência atual de que essa reentrância forneça uma janela de UAF; ela deve permanecer abaixo da análise do syscall 624 e do levantamento de slots Sony.

## Ordem recomendada

1. Executar 53a em conexões isoladas e comparar os offsets com `kinfo_proc` completo e `fstat`.
2. Executar 53b em várias conexões, anotando o valor inicial e a resposta a cada degrau de alocação.
3. Executar 53c somente se a console puder ser reiniciada entre tentativas; isolar imediatamente o último syscall antes de qualquer kill.
4. Atualizar a fila de teorias com os resultados. Não promover um valor para “kernel pointer” sem as três propriedades: faixa plausível, não-sentinela e correlação estrutural.
5. Deixar AF_ROUTE, kldstat/kldsym, AIO e rede malformada em estado morto até surgir uma mudança concreta no firmware, no argumento ou no caminho de dispatch.

## Referências

[1]: https://cgit.freebsd.org/src/tree/sys/kern/kern_sysctl.c "FreeBSD kern_sysctl.c source"
[2]: https://cgit.freebsd.org/src/tree/sys/vm/vm_meter.c "FreeBSD vm_meter.c source"
[3]: https://cgit.freebsd.org/src/tree/sys/kern/kern_descrip.c "FreeBSD kern_descrip.c source"
[4]: https://github.com/freebsd/freebsd-src/blob/main/sys/netinet/ip_input.c "FreeBSD ip_input.c source"
[5]: https://cgit.freebsd.org/src/tree/sys/kern/syscalls.master "FreeBSD syscall master table"
[6]: https://man.freebsd.org/cgi/man.cgi?query=sysctl&sektion=8&manpath=FreeBSD+14.0-RELEASE "FreeBSD sysctl(8) manual"
