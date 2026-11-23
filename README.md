# TableTop_MaquinaContaminada
Exercício tabletop de forense digital e resposta a incidentes, baseado na história fictícia de uma máquina comprometida por um anexo de e-mail.


# TableTop SITALKS · Máquina Contaminada

Exercício prático de **forense digital e resposta a incidentes**, no formato *tabletop*.

## O que é um tabletop?

Um *tabletop* é um exercício de simulação em que uma equipe enfrenta um incidente fictício, mas realista, e precisa analisar a situação, discutir e tomar decisões juntos, como faria num caso real.

## A história

O desafio foi elaborado a partir da história fictícia da Ana, do setor Financeiro. Ela recebeu um e-mail com uma suposta "nota fiscal", abriu o anexo e, sem perceber, comprometeu o próprio computador. Os participantes do tabletop assumem o papel da equipe de resposta. Eles investigam a máquina da Ana e analisam o e-mail, o arquivo baixado, os alertas de segurança e os usuários do sistema. No final, decidem como conter o ataque e como evitar que ele se repita.

## Intenção do projeto

O objetivo é mostrar, na prática, como um único clique pode comprometer uma instituição e como uma equipe deve agir depois disso. O exercício treina o olhar investigativo, a tomada de decisão sob pressão de tempo e o trabalho em equipe. Também reforça a mensagem principal de que um ambiente digital seguro começa com as atitudes de cada pessoa.

## Como funciona

Tudo roda numa máquina Windows de teste. O exercício cria as evidências (arquivos, logs, alertas e um usuário suspeito) e abre um painel no navegador onde os grupos respondem aos desafios, acompanham a pontuação e o cronômetro. As fases são liberadas por senhas mostradas no telão.

> Nada aqui é malware real. Tudo é simulado e pode ser removido com o `Limpar.cmd`.

## Pastas

| Pasta | O que tem |
|---|---|
| `MaquinaContaminada/` | Versão completa, com mais casos de investigação, como persistência na máquina e saída de dados |
| `MaquinaContaminada_VReduzida/` | Versão reduzida de 45 minutos, com 3 fases e 2 desafios em cada |
| `Materiais/` | Guia do instrutor, slides, roteiro impresso e papel de parede |

## Senhas de acesso

| Fase | Versão completa | Versão reduzida |
|---|---|---|
| 1 | `TRIAGEM` | `TRIAGEM` |
| 2 | `CONTENCAO` | `ANALISE` |
| 3 | `RESPOSTA` | `RESPOSTA` |

## Como usar

1. Use uma VM, o Windows Sandbox ou uma máquina de teste com Windows 10/11.
2. Copie a pasta da versão escolhida. Se ela veio em zip, desbloqueie antes de extrair, clicando com o botão direito › Propriedades › Desbloquear.
3. Dê dois cliques em `Iniciar.cmd` e digite a senha da fase.
4. Ao final, ou entre um grupo e outro, rode `Limpar.cmd`.
