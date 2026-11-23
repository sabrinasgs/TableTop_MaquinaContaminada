<#
  Tabletop "Máquina Contaminada" — motor da simulação
  -----------------------------------------------------
  SEGURO: não baixa nada, não abre portas, não executa código malicioso.
  Apenas cria arquivos de texto, eventos num log próprio (Simulacao-EDR),
  uma chave Run e uma tarefa agendada que apontam para um script inofensivo,
  e uma conta local — tudo DENTRO da VM e removível com -Limpar.

  Uso (PowerShell 5.1 como Administrador, dentro da VM):
     .\Simulacao.ps1                 -> pede o código da fase
     .\Simulacao.ps1 -Codigo SITALKS  -> libera a fase correspondente
     .\Simulacao.ps1 -Limpar         -> remove tudo o que a simulação criou
     .\Simulacao.ps1 -SemEICAR       -> não grava o arquivo de teste EICAR
#>
[CmdletBinding()]
param(
    [string]$Codigo,
    [switch]$Limpar,
    [switch]$SemEICAR,
    [switch]$ForcarVM
)

$ErrorActionPreference = 'Stop'
$Raiz      = 'C:\SimulacaoIR'
$Estado    = Join-Path $Raiz 'estado.json'
$LogNome   = 'Simulacao-EDR'
$LogFonte  = 'EDR-Simulado'
$Downloads = Join-Path $env:USERPROFILE 'Downloads'
$Desktop   = [Environment]::GetFolderPath('Desktop')
$PastaFases = Join-Path $PSScriptRoot 'fases'

function Escrever([string]$t, [string]$cor = 'Gray') { Write-Host $t -ForegroundColor $cor }

function Banner {
    Escrever ''
    Escrever '==============================================================' Cyan
    Escrever '   TABLETOP  -  MÁQUINA CONTAMINADA   (simulação de treinamento)' Cyan
    Escrever '==============================================================' Cyan
    Escrever '   Nenhum malware real. Tudo aqui é inofensivo e removível.' DarkGray
    Escrever ''
}

# ---------------------------------------------------------------- verificações
function Test-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-VM {
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $txt  = "$($cs.Manufacturer) $($cs.Model) $($bios.Manufacturer) $($bios.SMBIOSBIOSVersion) $($bios.Version) $($bios.SerialNumber)"
    return ($txt -match 'Virtual|VMware|VirtualBox|VBOX|innotek|KVM|QEMU|Xen|Parallels|Bochs|UTM|Hyper-V')
}

function Assert-Ambiente {
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'Use o Windows PowerShell 5.1 (powershell.exe), não o PowerShell 7. O arquivo Iniciar.cmd já faz isso.'
    }
    if (-not (Test-Admin)) { throw 'Execute como Administrador (use o Iniciar.cmd).' }
    if (-not (Test-VM)) {
        Escrever 'Aviso: este computador não parece ser uma máquina virtual. Use apenas uma máquina de teste.' Yellow
        Escrever 'Ao final, rode Limpar.cmd para remover a conta, a tarefa e os demais artefatos da simulação.' Yellow
    }
}

# ---------------------------------------------------------------- estado
function Ler-Estado {
    if (Test-Path $Estado) {
        $e = Get-Content $Estado -Raw -Encoding UTF8 | ConvertFrom-Json
        $ag = ''; if ($e.PSObject.Properties['agora']) { $ag = [string]$e.agora }
        $ds = @(); if ($e.PSObject.Properties['desafios']) { $ds = @($e.desafios) }
        $ini = ''; if ($e.PSObject.Properties['inicio']) { $ini = [string]$e.inicio }
        return [pscustomobject]@{ base = [datetime]$e.base; fases = @($e.fases); alertas = @($e.alertas); agora = $ag; desafios = $ds; inicio = $ini }
    }
    $b = (Get-Date).AddMinutes(-35)
    $b = $b.AddSeconds(-$b.Second).AddMilliseconds(-$b.Millisecond)
    return [pscustomobject]@{ base = $b; fases = @(); alertas = @(); agora = ''; desafios = @(); inicio = '' }
}

function Salvar-Estado($e) {
    New-Item -ItemType Directory -Force -Path $Raiz | Out-Null
    $obj = [ordered]@{ base = $e.base.ToString('o'); fases = @($e.fases); alertas = @($e.alertas); agora = [string]$e.agora; desafios = @($e.desafios); inicio = [string]$e.inicio }
    $json = ConvertTo-Json $obj -Depth 6
    [IO.File]::WriteAllText($Estado, $json, (New-Object Text.UTF8Encoding $false))
}

# ---------------------------------------------------------------- utilitários
function Expandir([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return $s }
    $r = $s.Replace('{DOWNLOADS}', $Downloads).Replace('{DESKTOP}', $Desktop).
            Replace('{USERPROFILE}', $env:USERPROFILE).Replace('{USER}', "$env:COMPUTERNAME\$env:USERNAME").
            Replace('{HOST}', $env:COMPUTERNAME)
    $avaliador = [Text.RegularExpressions.MatchEvaluator] {
        param($m)
        $d = $script:EstadoAtual.base.AddMinutes([int]$m.Groups[2].Value)
        switch ($m.Groups[1].Value) {
            'T'   { $d.ToString('yyyy-MM-dd HH:mm:ss') }
            'U'   { $d.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff') }
            'RFC' { $d.ToString('ddd, dd MMM yyyy HH:mm:ss ', [Globalization.CultureInfo]::InvariantCulture) + ($d.ToString('zzz') -replace ':', '') }
        }
    }
    return [regex]::Replace($r, '\{(T|U|RFC)\+(-?\d+)\}', $avaliador)
}

function Tem($obj, [string]$nome) { return ($null -ne $obj.PSObject.Properties[$nome]) }

function Gravar-Texto([string]$caminho, [string]$conteudo) {
    New-Item -ItemType Directory -Force -Path (Split-Path $caminho) | Out-Null
    [IO.File]::WriteAllText($caminho, $conteudo, (New-Object Text.UTF8Encoding $false))
}

function Ajustar-Hora([string]$caminho, $minutos) {
    if ($null -eq $minutos -or -not (Test-Path -LiteralPath $caminho)) { return }
    $d = $script:EstadoAtual.base.AddMinutes([int]$minutos)
    $i = Get-Item -LiteralPath $caminho -Force
    $i.CreationTime = $d; $i.LastWriteTime = $d; $i.LastAccessTime = $d
}

function Marcar-Internet([string]$caminho, $motw) {
    $linhas = @('[ZoneTransfer]', "ZoneId=$($motw.ZoneId)")
    if (Tem $motw 'ReferrerUrl') { $linhas += 'ReferrerUrl=' + (Expandir $motw.ReferrerUrl) }
    if (Tem $motw 'HostUrl')     { $linhas += 'HostUrl='     + (Expandir $motw.HostUrl) }
    Set-Content -LiteralPath $caminho -Stream 'Zone.Identifier' -Value $linhas -Encoding Ascii
}

function Ocultar([string]$caminho) {
    $i = Get-Item -LiteralPath $caminho -Force
    $i.Attributes = $i.Attributes -bor [IO.FileAttributes]::Hidden
}

function Abrir-Fase([string]$cod) {
    $chave = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($cod.Trim().ToUpperInvariant()))
    foreach ($f in Get-ChildItem $PastaFases -Filter 'fase*.dat' | Sort-Object Name) {
        try {
            $bytes = [Convert]::FromBase64String((Get-Content $f.FullName -Raw).Trim())
            $aes = [Security.Cryptography.Aes]::Create()
            $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $chave
            $aes.IV = [byte[]]($bytes[0..15])
            $plano = $aes.CreateDecryptor().TransformFinalBlock($bytes, 16, $bytes.Length - 16)
            return ([Text.Encoding]::UTF8.GetString($plano) | ConvertFrom-Json)
        } catch { continue }
    }
    return $null
}

# ---------------------------------------------------------------- ações
function Acao-Arquivo($a) {
    $p = Expandir $a.caminho
    if ((Tem $a 'eicar') -and $a.eicar) {
        if ($SemEICAR) { return }
        try {
            Gravar-Texto $p $a.conteudo
            Escrever '   (arquivo de teste EICAR gravado - o Defender pode gerar um alerta, isso é esperado)' DarkYellow
        } catch { Escrever '   (o antivírus bloqueou o arquivo de teste EICAR - isso também é uma pista)' DarkYellow }
        try { Ajustar-Hora $p $a.t } catch {}
        return
    }
    Gravar-Texto $p (Expandir $a.conteudo)
    if (Tem $a 'motw') { Marcar-Internet $p $a.motw }
    if ((Tem $a 'oculto') -and $a.oculto) { Ocultar $p; Ocultar (Split-Path $p) }
    if (Tem $a 't') {
        Ajustar-Hora $p $a.t
        $pai = Split-Path $p
        if ($pai -ne $Downloads -and $pai -ne $Desktop) { try { Ajustar-Hora $pai $a.t } catch {} }
    }
}

function Acao-Anexar($a) {
    $p = Expandir $a.caminho
    [IO.File]::AppendAllText($p, (Expandir $a.conteudo), (New-Object Text.UTF8Encoding $false))
}

function Acao-Zip($a) {
    $dest = Expandir $a.destino
    $tmp = Join-Path $env:TEMP ('simzip_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    foreach ($it in $a.itens) {
        $p = Join-Path $tmp $it.nome
        Gravar-Texto $p (Expandir $it.conteudo)
        if (Tem $a 't') { Ajustar-Hora $p ([int]$a.t - 1) }
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
    Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $dest -Force
    Remove-Item $tmp -Recurse -Force
    if (Tem $a 'motw') { Marcar-Internet $dest $a.motw }
    if (Tem $a 't') { Ajustar-Hora $dest $a.t }
    if ((Tem $a 'oculto_pasta') -and $a.oculto_pasta) { Ocultar (Split-Path $dest); Ocultar (Split-Path (Split-Path $dest)) }
}

function Acao-Evento($a) {
    if (-not [Diagnostics.EventLog]::SourceExists($LogFonte)) {
        New-EventLog -LogName $LogNome -Source $LogFonte
        Limit-EventLog -LogName $LogNome -MaximumSize 5MB -OverflowAction OverwriteAsNeeded
    }
    Write-EventLog -LogName $LogNome -Source $LogFonte -EventId ([int]$a.id) -EntryType $a.nivel -Message (Expandir $a.mensagem)
}

function Acao-Registro($a) {
    if (-not (Test-Path $a.chave)) { New-Item -Path $a.chave -Force | Out-Null }
    New-ItemProperty -Path $a.chave -Name $a.nome -Value $a.valor -PropertyType String -Force | Out-Null
}

function Acao-Tarefa($a) {
    $acao = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-w hidden -ep bypass -File `"$($a.script)`""
    $gat  = New-ScheduledTaskTrigger -Daily -At '03:00'
    $t    = New-ScheduledTask -Action $acao -Trigger $gat -Description $a.descricao
    try { $t.Author = $a.autor } catch {}
    Register-ScheduledTask -TaskName $a.nome -InputObject $t -Force | Out-Null
}

function Acao-Usuario($a) {
    if (Get-LocalUser -Name $a.nome -ErrorAction SilentlyContinue) { return }
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%'
    $senha = (-join (1..18 | ForEach-Object { $chars | Get-Random })) + 'Aa9!'
    $seg = ConvertTo-SecureString $senha -AsPlainText -Force
    New-LocalUser -Name $a.nome -Password $seg -Description $a.descricao -AccountNeverExpires | Out-Null
    if ($a.admin) { Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $a.nome }
}

function Acao-Alerta($a, $e) {
    $e.alertas = @($e.alertas) + [pscustomobject]@{
        hora = (Expandir ('{T+' + $a.t + '}')); sev = $a.sev; titulo = $a.titulo; texto = $a.texto
    }
}

function Registrar-Protocolo {
    # Permite que o botão do Painel de Alertas abra o Iniciar.cmd (link sitalks://)
    $iniciar = Join-Path (Split-Path $PSScriptRoot -Parent) 'Iniciar.cmd'
    if (-not (Test-Path $iniciar)) { return }
    $k = 'HKCU:\Software\Classes\sitalks'
    New-Item -Path "$k\shell\open\command" -Force | Out-Null
    Set-ItemProperty -Path $k -Name '(default)' -Value 'URL:TableTop SITALKS'
    New-ItemProperty -Path $k -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null
    Set-ItemProperty -Path "$k\shell\open\command" -Name '(default)' -Value ('"{0}\System32\cmd.exe" /c ""{1}""' -f $env:windir, $iniciar)
}

# ---------------------------------------------------------------- painel visual
$script:JsPainel = @'
var D = JSON.parse(document.getElementById('dados').textContent);
var NOMES = {1:'Fase 1 · Como o atacante entrou', 2:'Fase 2 · Como o atacante ficou', 3:'Fase 3 · O que o atacante fez'};
var PONTO = 10, CUSTO = {dica: 5, cmd: 10}, TEMPO = 45 * 60;
var ESTADO = {}, ACERTOS = {};
function K(s){ return 'sit-' + D.run + '-' + s; }
function salvar(k, v){ try { localStorage.setItem(K(k), v); } catch(e) {} }
function ler(k){ try { return localStorage.getItem(K(k)) || ''; } catch(e) { return ''; } }
function usadas(){ try { return JSON.parse(ler('dicas') || '[]'); } catch(e) { return []; } }
function norm(s){ return (s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim(); }
function fnv(t){ var h = 0x811c9dc5; for (var i = 0; i < t.length; i++) { h ^= (t.charCodeAt(i) & 255); h = Math.imul(h, 16777619) >>> 0; } return ('0000000' + h.toString(16)).slice(-8); }
function toks(s){ return norm(s).split(/[\s,;:@\/\\()<>"'|=?&]+/).map(function(t){ return t.replace(/^[.\-]+|[.\-]+$/g, ''); }).filter(function(t){ return t.length > 0; }); }
function el(tag, cls, txt){ var x = document.createElement(tag); if (cls) x.className = cls; if (txt !== undefined) x.textContent = txt; return x; }
function todasFases(){ return Object.keys(D.fases).map(Number).sort(); }

function confere(c, v){
  if (v === null || v === undefined || v === '') return null;
  if (c.tipo === 'num') { var m = norm(v).replace(',', '.').match(/\d+(\.\d+)?/); if (!m) return false; var n = parseFloat(m[0]); return n >= c.min && n <= c.max; }
  if (c.tipo === 'opcao' || c.tipo === 'multi') return c.h.indexOf(fnv(norm(v))) >= 0;
  var ts = toks(v);
  return ts.some(function(t){ return c.h.indexOf(fnv(t)) >= 0 || (c.p8 && c.h.indexOf(fnv(t.slice(0, 8))) >= 0); });
}
function valor(card, d, i, c){
  if (c.tipo === 'opcao') { var r = card.querySelector('input[name="op-' + d.id + '-' + i + '"]:checked'); return r ? r.value : ''; }
  if (c.tipo === 'multi') { var cs = card.querySelectorAll('input[name="mu-' + d.id + '-' + i + '"]:checked'); var a = []; cs.forEach(function(x){ a.push(norm(x.value)); }); a.sort(); return a.join('|'); }
  return card.querySelector('#in-' + d.id + '-' + i).value;
}

/* ---------- pontos e cronometro ---------- */
function totalCampos(){ var n = 0; todasFases().forEach(function(f){ D.fases[f].d.forEach(function(d){ n += d.campos.length; }); }); return n; }
function pontos(){
  var p = 0;
  todasFases().forEach(function(f){ D.fases[f].d.forEach(function(d){ d.campos.forEach(function(c, i){ if (confere(c, ler('v-' + d.id + '-' + i)) === true) p += PONTO; }); }); });
  usadas().forEach(function(u){ p -= CUSTO[u.split(':')[1]] || 0; });
  return Math.max(0, p);
}
function atualizarPlacar(){
  document.getElementById('pts').textContent = pontos();
  document.getElementById('ptsmax').textContent = 'Máximo possível até agora: ' + (totalCampos() * PONTO) + ' pontos.';
}
function inicio(){ var v = parseInt(ler('inicio') || '0', 10); return v > 0 ? v : 0; }
function agoraOuFim(){ var f = parseInt(ler('fim') || '0', 10); return f > 0 ? f : Date.now(); }
var TRAVADO = false;
function relogio(){
  var fim = parseInt(ler('fim') || '0', 10), box0 = document.getElementById('relogio');
  if (!inicio()) { document.getElementById('tempo').textContent = '45:00'; box0.className = 'kpi'; document.getElementById('tempolbl').textContent = 'aguardando início'; return; }
  var rest = Math.round(TEMPO - (agoraOuFim() - inicio()) / 1000), box = document.getElementById('relogio'), t = document.getElementById('tempo');
  if (fim > 0) { rest = Math.max(0, rest); var mm = Math.floor(rest / 60), ss = rest % 60; t.textContent = (mm < 10 ? '0' : '') + mm + ':' + (ss < 10 ? '0' : '') + ss; box.className = 'kpi parado'; document.getElementById('tempolbl').textContent = 'finalizado'; return; }
  if (rest <= 0) { t.textContent = '00:00'; box.className = 'kpi fim'; document.getElementById('tempolbl').textContent = 'tempo esgotado'; esgotou(); return; }
  var m = Math.floor(rest / 60), s = rest % 60; t.textContent = (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
  box.className = rest < 300 ? 'kpi alerta' : 'kpi'; document.getElementById('tempolbl').textContent = 'tempo restante';
}
function esgotou(){
  if (TRAVADO) return; TRAVADO = true;
  document.querySelectorAll('input, button, textarea').forEach(function(x){ x.disabled = true; });
  document.querySelectorAll('a.sec').forEach(function(x){ x.style.pointerEvents = 'none'; });
  var m = document.getElementById('modal'); m.className = 'final esgotado';
  m.innerHTML = '<div class="escudo vermelho">⏰</div><h3>Tempo esgotado!</h3><p class="sub2">Os 45 minutos acabaram e as respostas foram bloqueadas.</p>' +
    '<p class="sub2">Para tentar de novo, comecem do início:</p><ol class="passos"><li>Fechem esta página.</li><li>Na pasta do kit, deem duplo clique em <b>Limpar.cmd</b> e digitem <b>S</b>.</li><li>Deem duplo clique em <b>Iniciar.cmd</b> e digitem o código da Fase 1 mostrado no telão.</li></ol>' +
    '<p class="sub2">Pontos nesta tentativa: <b>' + pontos() + '</b></p>';
  document.getElementById('fundo').style.display = 'flex';
}
function tempoUsado(){ var s = Math.max(0, Math.round((agoraOuFim() - inicio()) / 1000)); var m = Math.floor(s / 60); return m + ' min ' + (s % 60) + ' s'; }

/* ---------- desafios ---------- */
function avaliar(d, card, mostrar){
  var antes = (D.fases[D.atual] ? faltam(D.atual) : 1), ok = true, algum = false;
  d.campos.forEach(function(c, i){
    var v = valor(card, d, i, c); salvar('v-' + d.id + '-' + i, v);
    var r = confere(c, v), st = card.querySelector('#st-' + d.id + '-' + i), alvo = card.querySelector('#bx-' + d.id + '-' + i);
    alvo.classList.remove('certo', 'errado'); st.textContent = '';
    ACERTOS[d.id + '-' + i] = (r === true);
    if (r === true) { alvo.classList.add('certo'); st.textContent = '✔'; st.style.color = '#4ade80'; algum = true; }
    else if (r === false) { alvo.classList.add('errado'); st.textContent = '✘'; st.style.color = '#f87171'; algum = true; ok = false; }
    else ok = false;
  });
  var fb = card.querySelector('.fb'); fb.className = 'fb';
  if (ok) { fb.className = 'fb ok'; fb.textContent = '✔ Certo! ' + d.ok; card.classList.add('ok'); }
  else { card.classList.remove('ok'); if (mostrar && algum) { fb.className = 'fb no'; fb.textContent = 'Ainda não. Revejam os campos com ✘: voltem à evidência, abram a dica ou sigam o Roteiro.'; } }
  ESTADO[d.id] = ok; atualizarFases(); atualizarPlacar();
  if (mostrar && ok && antes > 0 && faltam(D.atual) === 0 && D.fases[D.atual].d.indexOf(d) >= 0 && !TRAVADO) setTimeout(abrir, 700);
}
function faltam(f){ return D.fases[f].d.filter(function(d){ return !ESTADO[d.id]; }).length; }
function atualizarFases(){
  todasFases().forEach(function(f){ var b = document.getElementById('fim-' + f); if (b) b.style.display = faltam(f) === 0 ? 'block' : 'none'; });
  var n = faltam(D.atual), tot = D.fases[D.atual].d.length, btn = document.getElementById('btnfase');
  btn.textContent = D.atual < 3 ? '✔ Concluir a Fase ' + D.atual : '✔ Concluir a investigação';
  btn.disabled = n > 0 || TRAVADO;
  document.getElementById('rodtxt').innerHTML = n > 0 ? '<b>Fase ' + D.atual + ':</b> ' + (tot - n) + ' de ' + tot + ' desafios corretos. O botão libera quando todas as respostas estiverem conferidas e certas.'
                                                       : '<b>Fase ' + D.atual + ' completa!</b> Todas as respostas estão certas.';
  document.getElementById('rodape').className = n > 0 ? '' : 'pronto';
}
function campoHTML(card, d, c, i){
  var linha = el('div', 'cp'); linha.appendChild(el('label', '', c.rot));
  var salvo = ler('v-' + d.id + '-' + i), box;
  if (c.tipo === 'opcao' || c.tipo === 'multi') {
    box = el('div', c.tipo === 'opcao' ? 'ops' : 'ops multi');
    c.op.forEach(function(o){
      var lb = el('label', 'op'), inp = el('input');
      inp.type = c.tipo === 'opcao' ? 'radio' : 'checkbox'; inp.name = (c.tipo === 'opcao' ? 'op-' : 'mu-') + d.id + '-' + i; inp.value = o;
      if (c.tipo === 'opcao' ? salvo === o : salvo.split('|').indexOf(norm(o)) >= 0) inp.checked = true;
      lb.appendChild(inp); lb.appendChild(document.createTextNode(' ' + o)); box.appendChild(lb);
    });
  } else {
    box = el('input'); box.id = 'in-' + d.id + '-' + i; box.placeholder = c.ph || ''; box.value = salvo;
    box.addEventListener('keydown', function(ev){ if (ev.key === 'Enter') avaliar(d, card, true); });
  }
  box.id = box.id || ''; var wrap = el('div', 'bx'); wrap.id = 'bx-' + d.id + '-' + i; wrap.appendChild(box);
  linha.appendChild(wrap); var st = el('span', 'st'); st.id = 'st-' + d.id + '-' + i; linha.appendChild(st);
  return linha;
}
function montarDesafios(){
  var raiz = document.getElementById('aba-desafios');
  todasFases().forEach(function(f){
    var antiga = f < D.atual, box = el(antiga ? 'details' : 'div', 'fd'), cab = el(antiga ? 'summary' : 'div', 'fh');
    cab.appendChild(el('span', '', NOMES[f])); cab.appendChild(el('small', '', antiga ? 'concluída · clique para rever' : 'fase atual')); box.appendChild(cab);
    D.fases[f].d.forEach(function(d, k){
      var card = el('div', 'dc'), h = el('h3'); h.appendChild(el('span', 'nn', String(k + 1))); h.appendChild(document.createTextNode(d.titulo)); card.appendChild(h);
      card.appendChild(el('p', 'ms', d.missao));
      d.campos.forEach(function(c, i){ card.appendChild(campoHTML(card, d, c, i)); });
      var bt = el('div', 'bt'), b1 = el('button', 'btn', 'Conferir resposta'), b2 = el('button', 'dicab', 'Ver dica inicial (grátis)'), dt = el('div', 'dt', 'Dica: ' + d.dica);
      b1.onclick = function(){ avaliar(d, card, true); };
      b2.onclick = function(){ dt.style.display = dt.style.display === 'block' ? 'none' : 'block'; };
      var b3 = el('a', 'sec', 'Precisa de mais ajuda? Ir para o Roteiro'); b3.href = '#roteiro'; b3.onclick = function(ev){ return irAba(ev, 'roteiro'); };
      bt.appendChild(b1); bt.appendChild(b2); bt.appendChild(b3); card.appendChild(bt); card.appendChild(dt); card.appendChild(el('div', 'fb'));
      box.appendChild(card); avaliar(d, card, false);
    });
    var fim = el('div', 'fasefim', f < 3 ? '✔ Fase ' + f + ' concluída! Cliquem em “Concluir a Fase ' + f + '” no rodapé da página.' : '✔ Todos os desafios resolvidos! Cliquem em “Concluir a investigação” no rodapé.');
    fim.id = 'fim-' + f; box.appendChild(fim); raiz.appendChild(box);
  });
}

/* ---------- roteiro (passos + dicas pagas) ---------- */
function revelar(id, tipo, alvo, btn){
  var u = usadas(), chave = id + ':' + tipo;
  if (u.indexOf(chave) < 0) {
    if (btn.dataset.conf !== '1') { btn.dataset.conf = '1'; btn.textContent = 'Confirmar: perder ' + CUSTO[tipo] + ' pontos?'; btn.classList.add('confirma'); return; }
    u.push(chave); salvar('dicas', JSON.stringify(u)); atualizarPlacar();
  }
  alvo.style.display = 'block'; btn.style.display = 'none';
}
function copiar(txt, b){ var ok = function(){ b.textContent = 'Copiado!'; setTimeout(function(){ b.textContent = 'Copiar'; }, 1500); };
  try { navigator.clipboard.writeText(txt).then(ok, function(){ copiaVelha(txt); ok(); }); } catch(e) { copiaVelha(txt); ok(); } }
function copiaVelha(t){ var a = document.createElement('textarea'); a.value = t; document.body.appendChild(a); a.select(); try { document.execCommand('copy'); } catch(e) {} document.body.removeChild(a); }
function marcarCampos(c){ var t = c.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); return t.replace(/\b[A-Z]+(?:_[A-Z]+)+\b/g, '<span class="ph" title="Troque pelo valor certo">$&</span>'); }
function blocoCmd(c){ var w = el('div', 'cmd'), code = el('code'), b = el('button', '', 'Copiar'); code.innerHTML = marcarCampos(c); if (/\b[A-Z]+(?:_[A-Z]+)+\b/.test(c)) w.classList.add('preencher'); b.onclick = function(){ copiar(c, b); }; w.appendChild(code); w.appendChild(b); return w; }
function progresso(){
  var tot = 0, fe = 0; document.querySelectorAll('.passo input.feito').forEach(function(c){ tot++; if (c.checked) fe++; });
  document.getElementById('prog-rot').textContent = fe + ' de ' + tot + ' passos feitos';
  document.getElementById('bar-rot').style.width = (tot ? 100 * fe / tot : 0) + '%';
}
function montarRoteiro(){
  var raiz = document.getElementById('lista-rot'), u = usadas();
  todasFases().forEach(function(f){
    var antiga = f < D.atual, box = el(antiga ? 'details' : 'div', 'fd'), cab = el(antiga ? 'summary' : 'div', 'fh');
    cab.appendChild(el('span', '', NOMES[f])); cab.appendChild(el('small', '', antiga ? 'clique para rever' : 'siga na ordem')); box.appendChild(cab);
    D.fases[f].r.forEach(function(p, k){
      var s = el('div', 'passo'), topo = el('div', 'ptopo'), chk = el('input', 'feito'); chk.type = 'checkbox'; chk.checked = ler('chk-' + p.id) === '1';
      chk.onchange = function(){ salvar('chk-' + p.id, chk.checked ? '1' : ''); s.classList.toggle('feito-ok', chk.checked); progresso(); };
      s.classList.toggle('feito-ok', chk.checked);
      var lb = el('label', 'ptit'); lb.appendChild(chk); lb.appendChild(document.createTextNode(' Passo ' + (k + 1) + ' · ' + p.titulo)); topo.appendChild(lb);
      topo.appendChild(el('span', 'chip', 'Responde ao desafio ' + p.d.split('-D')[1])); s.appendChild(topo);
      s.appendChild(el('p', 'ptxt', p.texto));
      var bts = el('div', 'bt'), dd = el('div', 'dt', 'Dica detalhada: ' + p.dica), cc = el('div', 'dt'); dd.id = 'dd-' + p.id; cc.id = 'cc-' + p.id; chk.id = 'ck-' + p.id;
      if (p.cmd.length > 1) cc.appendChild(el('div', 'seq', 'Execute na ordem, um depois do outro:'));
      p.cmd.forEach(function(c, k){ var bc = blocoCmd(c); if (p.cmd.length > 1) bc.insertBefore(el('span', 'ord', (k + 1) + '\u00BA'), bc.firstChild); cc.appendChild(bc); });
      var b1 = el('button', 'dicab', 'Dica detalhada (−' + CUSTO.dica + ' pts)'); b1.id = 'b1-' + p.id; b1.onclick = function(){ revelar(p.id, 'dica', dd, b1); }; bts.appendChild(b1);
      if (p.cmd.length) { var b2 = el('button', 'dicab cmdb', 'Comando pronto (−' + CUSTO.cmd + ' pts)'); b2.id = 'b2-' + p.id; b2.onclick = function(){ revelar(p.id, 'cmd', cc, b2); }; bts.appendChild(b2); if (u.indexOf(p.id + ':cmd') >= 0) { cc.style.display = 'block'; b2.style.display = 'none'; } }
      if (u.indexOf(p.id + ':dica') >= 0) { dd.style.display = 'block'; b1.style.display = 'none'; }
      s.appendChild(bts); s.appendChild(dd); s.appendChild(cc); box.appendChild(s);
    });
    raiz.appendChild(box);
  });
  progresso();
}

/* ---------- comandos ---------- */
function montarComandos(){
  var raiz = document.getElementById('aba-comandos');
  todasFases().forEach(function(f){
    var antiga = f < D.atual, sec = el(antiga ? 'details' : 'div', 'fd'), cab = el(antiga ? 'summary' : 'div', 'fh');
    cab.appendChild(el('span', '', 'Comandos da ' + NOMES[f])); cab.appendChild(el('small', '', antiga ? 'clique para rever' : 'fase atual')); sec.appendChild(cab);
    (D.fases[f].c || []).forEach(function(g){
      sec.appendChild(el('div', 'gcmd', g[0]));
      g[1].forEach(function(it){ var l = el('div', 'cmdl'); l.appendChild(blocoCmd(it[0])); l.appendChild(el('p', '', it[1])); sec.appendChild(l); });
    });
    if (antiga) raiz.appendChild(sec); else raiz.insertBefore(sec, raiz.querySelector('.fd'));
  });
}

/* ---------- abas, modal e final ---------- */
function irAba(ev, n){ if (ev && (ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.button === 1)) return true; if (ev) ev.preventDefault(); aba(n); try { history.replaceState(null, '', '#' + n); } catch(e) {} return false; }
function aba(n){ ['desafios', 'roteiro', 'comandos'].forEach(function(a){ document.getElementById('aba-' + a).style.display = a === n ? 'block' : 'none'; document.getElementById('tab-' + a).classList.toggle('ativa', a === n); }); window.scrollTo(0, 0); }
function abrir(){
  var m = document.getElementById('modal'), f = D.atual, n = faltam(f), h = '';
  if (f >= 3 && n === 0) { final(); return; }
  if (n > 0) return;
  if (true) h = '<h3>Fase ' + f + ' concluída!</h3><p>Todas as respostas estão certas. Peguem o <b>código da Fase ' + (f + 1) + '</b> no telão.</p><div class="acoes"><button class="sec" onclick="fechar()">Agora não</button><a class="btn" href="sitalks://proxima-fase" onclick="fechar()">Abrir o Iniciar e digitar o código</a></div><p class="mini">O navegador vai perguntar se pode abrir o aplicativo: cliquem em Abrir. Se nada acontecer, deem duplo clique em Iniciar.cmd na pasta do kit.</p>';
  m.className = ''; m.innerHTML = h; document.getElementById('fundo').style.display = 'flex';
}
function fechar(){ if (TRAVADO) return; setTimeout(function(){ document.getElementById('fundo').style.display = 'none'; }, 300); }
function final(){
  if (!ler('fim')) salvar('fim', String(Date.now())); relogio();
  var m = document.getElementById('modal'), nd = usadas().length;
  m.className = 'final';
  m.innerHTML = '<div class="escudo">✔</div><h3>Incidente contido!</h3><p class="sub2">A equipe investigou o ataque de ponta a ponta e tomou as decisões certas para conter o incidente.</p>' +
    '<div class="kpis"><div><b>' + pontos() + '</b><span>pontos</span></div><div><b>' + tempoUsado() + '</b><span>tempo de investigação</span></div><div><b>' + nd + '</b><span>dicas compradas</span></div></div>' +
    '<ul><li>Identificaram o phishing: domínio falso, SPF e DMARC com falha.</li><li>Encontraram o script disfarçado, sua origem e sua hash.</li><li>Acharam a persistência e o servidor de comando do atacante.</li><li>Descobriram a conta criada e o vazamento de dados pessoais.</li><li>Decidiram conter, erradicar, recuperar e comunicar, em vez de “só rodar o antivírus”.</li></ul>' +
    '<p class="sub2"><b>Vocês agiram como um verdadeiro time de resposta a incidentes:</b> investigaram com método, seguiram as evidências e tomaram decisões que protegem pessoas e dados. A segurança da empresa começa exatamente assim. Parabéns!</p><div class="acoes"><button class="btn" onclick="fechar()">Fechar</button></div>';
  document.getElementById('fundo').style.display = 'flex';
}
function sincronizar(){
  usadas().forEach(function(u){ var a = u.split(':'), alvo = document.getElementById((a[1] === 'cmd' ? 'cc-' : 'dd-') + a[0]), b = document.getElementById((a[1] === 'cmd' ? 'b2-' : 'b1-') + a[0]); if (alvo) alvo.style.display = 'block'; if (b) b.style.display = 'none'; });
  document.querySelectorAll('.passo input.feito').forEach(function(c){ var id = c.id.slice(3); c.checked = ler('chk-' + id) === '1'; c.closest('.passo').classList.toggle('feito-ok', c.checked); });
  progresso(); atualizarPlacar(); relogio();
}
window.addEventListener('storage', sincronizar);
montarDesafios(); montarRoteiro(); montarComandos(); atualizarPlacar(); relogio(); setInterval(relogio, 1000);
var h0 = (location.hash || '').replace('#', ''); if (['desafios', 'roteiro', 'comandos'].indexOf(h0) >= 0) aba(h0);
/* ---------- notificacoes (alertas do SOC) ---------- */
var CORES = {CRITICA: '#ff4d5e', ALTA: '#ff8a3d', MEDIA: '#f5c242', BAIXA: '#a78bfa', INFO: '#7d8bd1'};
function chaveAlerta(a){ return fnv(norm(a.hora + a.titulo)); }
function cardAlerta(a, toast){
  var c = el('div', toast ? 'toast' : 'notif'); c.style.borderLeftColor = CORES[a.sev] || '#9aa4b2';
  var t = el('div', 'top'), sv = el('span', 'sev', a.sev); sv.style.background = CORES[a.sev] || '#9aa4b2'; t.appendChild(sv); t.appendChild(el('span', 'hora', a.hora));
  if (toast) { var x = el('button', 'x', '✕'); x.onclick = function(){ c.classList.add('sai'); setTimeout(function(){ c.remove(); }, 250); }; t.appendChild(x); }
  c.appendChild(t); c.appendChild(el('h4', '', a.titulo)); c.appendChild(el('p', '', a.texto)); return c;
}
function notificar(){
  var vistos = []; try { vistos = JSON.parse(ler('vistos') || '[]'); } catch(e) {}
  var lista = document.getElementById('sinolista'); lista.innerHTML = '';
  (D.alertas || []).forEach(function(a){ lista.appendChild(cardAlerta(a, false)); });
  document.getElementById('sinonum').textContent = (D.alertas || []).length;
  var novos = (D.alertas || []).filter(function(a){ return vistos.indexOf(chaveAlerta(a)) < 0; }).reverse(), pilha = document.getElementById('toasts');
  novos.forEach(function(a, i){ setTimeout(function(){ var c = cardAlerta(a, true); pilha.appendChild(c); setTimeout(function(){ c.classList.add('sai'); setTimeout(function(){ c.remove(); }, 250); }, 20000); }, 700 * (i + 1)); vistos.push(chaveAlerta(a)); });
  salvar('vistos', JSON.stringify(vistos));
}
function sino(){ var p = document.getElementById('sinopainel'); p.style.display = p.style.display === 'block' ? 'none' : 'block'; }
/* ---------- tour de boas-vindas (antes do cronometro) ---------- */
var TOUR = [
 ['Bem-vindos à Central de Alertas TableTop SITALKS', 'Vocês são o time de resposta a incidentes. O notebook da Ana (Financeiro) foi atacado depois que ela abriu uma “fatura”. Em 45 minutos, investiguem o ataque em 3 fases e decidam a resposta. O cronômetro só começa quando vocês clicarem em Começar, no último passo.'],
 ['Aba Desafios', 'Cada fase tem desafios com campos de resposta. Investiguem na máquina, preencham e cliquem em Conferir resposta: a página mostra na hora se está certo (✔) ou não (✘). Cada resposta certa vale 10 pontos. A dica inicial de cada desafio é grátis.'],
 ['Aba Roteiro e dicas', 'O passo a passo de cada fase. Marquem cada passo quando terminarem. Travou? A dica detalhada custa 5 pontos e o comando pronto custa 10, descontados no placar. Ctrl + clique na aba abre o Roteiro em outra janela.'],
 ['Aba Comandos', 'Todos os comandos da investigação, para copiar e colar no PowerShell (Menu Iniciar › PowerShell). Os trechos em amarelo, escritos em MAIÚSCULAS_COM_SUBLINHADO (ex.: CAMINHO_DO_ARQUIVO), são partes que vocês precisam trocar pelo arquivo ou pasta certos antes de apertar Enter.'],
 ['Notificações do SOC', 'Os alertas do SOC aparecem como notificações no canto da tela, a cada nova fase. Para rever todos, cliquem no sino no alto da página.'],
 ['Concluir a fase', 'O botão no rodapé da página só libera quando todas as respostas da fase estiverem conferidas e certas. Ao clicar, peguem o código da próxima fase no telão. Se o tempo acabar, o painel é bloqueado. Boa investigação!']
];
function tour(i){
  var m = document.getElementById('modal'), t = TOUR[i], ult = i === TOUR.length - 1, comecou = !!inicio();
  var dots = TOUR.map(function(_, k){ return '<i class="' + (k === i ? 'on' : '') + '"></i>'; }).join('');
  m.className = 'tour';
  m.innerHTML = '<div class="tnum">Passo ' + (i + 1) + ' de ' + TOUR.length + '</div><h3></h3><p class="sub2"></p><div class="dots">' + dots + '</div><div class="acoes">' +
    (i > 0 ? '<button class="sec" onclick="tour(' + (i - 1) + ')">Voltar</button>' : '') +
    (ult ? '<button class="btn" onclick="comecar()">' + (comecou ? 'Voltar à investigação' : 'Começar a investigação ▶') + '</button>' : '<button class="btn" onclick="tour(' + (i + 1) + ')">Próximo</button>') + '</div>';
  m.querySelector('h3').textContent = t[0]; m.querySelector('p').textContent = t[1];
  document.getElementById('fundo').style.display = 'flex';
}
function ajuda(){ if (!TRAVADO) tour(0); }
function comecar(){ if (!inicio()) salvar('inicio', String(Date.now())); document.getElementById('modal').className = ''; document.getElementById('fundo').style.display = 'none'; relogio(); notificar(); }
if (!inicio()) { if (D.atual > 1) { salvar('inicio', String(Date.now())); notificar(); } else tour(0); } else notificar();
relogio(); atualizarFases();
'@

function Gerar-Painel($e) {
    $enc = { param($s) [Net.WebUtility]::HtmlEncode([string]$s) }
    $cores = @{ CRITICA = '#ff4d5e'; ALTA = '#ff8a3d'; MEDIA = '#f5c242'; BAIXA = '#a78bfa'; INFO = '#7d8bd1' }
    $lista = @($e.alertas) | Sort-Object hora -Descending
    $cards = foreach ($al in $lista) {
        $c = $cores[[string]$al.sev]; if (-not $c) { $c = '#9aa4b2' }
        "<div class='card' style='border-left-color:$c'><div class='top'><span class='sev' style='background:$c'>$(& $enc $al.sev)</span><span class='hora'>$(& $enc $al.hora)</span></div><h3>$(& $enc $al.titulo)</h3><p>$(& $enc $al.texto)</p></div>"
    }
    $atual = (@($e.fases) | Measure-Object -Maximum).Maximum
    $nomes = @{ 1 = 'Como entrou'; 2 = 'Como ficou'; 3 = 'O que fez' }
    $etapas = foreach ($i in 1..3) {
        if ($i -lt $atual) { "<div class='et ok'><span>&#10003;</span>Fase $i &middot; $($nomes[$i])<small>concluída</small></div>" }
        elseif ($i -eq $atual) { "<div class='et at'><span>$i</span>Fase $i &middot; $($nomes[$i])<small>em andamento</small></div>" }
        else { "<div class='et bl'><span>$i</span>Fase $i &middot; $($nomes[$i])<small>bloqueada</small></div>" }
    }
    $partes = foreach ($d in @($e.desafios)) { '"{0}":{1}' -f [int]$d.fase, [string]$d.json }
    $ini = 0
    if ($e.inicio) { try { $ini = ([DateTimeOffset]::Parse([string]$e.inicio)).ToUnixTimeMilliseconds() } catch { $ini = 0 } }
    $alj = '[' + ((@($lista) | ForEach-Object { [pscustomobject]@{ sev = [string]$_.sev; hora = [string]$_.hora; titulo = [string]$_.titulo; texto = [string]$_.texto } | ConvertTo-Json -Compress }) -join ',') + ']'
    $dados = ('{{"atual":{0},"run":"{2}","inicio":{3},"alertas":{4},"fases":{{{1}}}}}' -f [int]$atual, ($partes -join ','), $e.base.ToString('yyyyMMddHHmm'), $ini, $alj) -replace '</', '<\/'
    $nAlertas = @($lista).Count
    $html = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<title>Central de Alertas - TableTop SITALKS (simulação)</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#07070c;color:#ece9f5}
header{padding:16px 28px;background:linear-gradient(90deg,#0b1437 0%,#1a1046 60%,#3b1680 100%);border-bottom:2px solid #7c3aed;display:flex;justify-content:space-between;align-items:center;gap:16px;position:sticky;top:0;z-index:5}
.brand{font-size:12px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#c4b5fd;margin-bottom:2px}
h1{font-size:20px;margin:0;color:#fff}.sub{color:#a9aed6;font-size:13px}
.host{font-family:Consolas,monospace;background:#2b1a5c;color:#ddd0ff;padding:2px 8px;border-radius:4px}
.kpis-top{display:flex;gap:10px}.kpi{background:rgba(0,0,0,.35);border:1px solid #4c1d95;border-radius:10px;padding:6px 14px;text-align:center;min-width:120px}
.kpi b{display:block;font-size:24px;color:#fff;font-variant-numeric:tabular-nums}.kpi small{font-size:11px;color:#c4b5fd;text-transform:uppercase;letter-spacing:.06em}
.kpi.alerta{border-color:#f5c242}.kpi.alerta b{color:#f5c242}.kpi.fim{border-color:#ef4444}.kpi.fim b{color:#f87171}.kpi.parado{border-color:#16a34a}.kpi.parado b{color:#4ade80}
.wrap{max-width:1040px;padding:0 28px 40px}
.etapas{display:flex;gap:10px;margin:18px 0 0}
.et{flex:1;display:flex;align-items:center;gap:10px;background:#0d1330;border:1px solid #262a5c;border-radius:10px;padding:10px 12px;font-size:14px;color:#cfd2ea}
.et span{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;background:#262a5c;color:#a9aed6;flex:none}
.et small{margin-left:auto;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:#6a6f99}
.et.ok{border-color:#16a34a}.et.ok span{background:#16a34a;color:#fff}.et.ok small{color:#4ade80}
.et.at{border-color:#7c3aed;background:#1a1046}.et.at span{background:#7c3aed;color:#fff}.et.at small{color:#c4b5fd}.et.bl{opacity:.55}
.agora{margin:14px 0 0;background:linear-gradient(90deg,#14215b,#3b1680);border:1px solid #7c3aed;border-radius:10px;padding:14px 18px}
.agora b{display:block;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#c4b5fd;margin-bottom:4px}.agora p{color:#fff;font-size:15px;margin:0}
.agora .linha{display:flex;align-items:center;gap:16px;justify-content:space-between}
.tabs{display:flex;gap:6px;margin:18px 0 0;border-bottom:1px solid #262a5c}
.tabs{align-items:flex-end}.tabs a{border-bottom:3px solid transparent;color:#a9aed6;font-size:15px;font-weight:600;padding:10px 16px;cursor:pointer;text-decoration:none}
.tabs a.ativa{color:#fff;border-bottom-color:#7c3aed}.tabs a span{background:#262a5c;border-radius:10px;padding:0 8px;font-size:12px;margin-left:4px}.dicaaba{margin-left:auto;color:#6a6f99;font-size:12px;padding-bottom:10px}
.aba{padding-top:16px}
.btn{display:inline-block;white-space:nowrap;background:#7c3aed;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:14.5px;font-weight:600;cursor:pointer;text-decoration:none;font-family:inherit}
.btn:hover{background:#6d28d9}.sec{background:transparent;color:#cfd2ea;border:1px solid #3b2a7a;border-radius:8px;padding:9px 14px;font-size:13.5px;cursor:pointer;font-family:inherit;text-decoration:none}
.fd{background:#0a0f26;border:1px solid #262a5c;border-radius:12px;margin-bottom:14px;overflow:hidden}
.fd>summary,.fh{list-style:none;cursor:pointer;padding:12px 18px;background:#11183a;font-weight:700;color:#fff;display:flex;justify-content:space-between}
.fd>summary::-webkit-details-marker{display:none}.fh small{font-weight:600;color:#a9aed6}
.dc,.passo{border-top:1px solid #1d2250;padding:14px 18px}.dc h3{margin:0 0 4px;font-size:16.5px;color:#fff;display:flex;gap:10px;align-items:center}
.nn{width:26px;height:26px;border-radius:50%;background:#7c3aed;color:#fff;font-size:13px;display:inline-flex;align-items:center;justify-content:center}
.dc.ok .nn{background:#16a34a}.ms{margin:2px 0 10px;color:#cfd2ea;font-size:14.5px}
.cp{display:grid;grid-template-columns:250px 1fr 26px;gap:10px;align-items:center;margin-bottom:8px}
.cp>label{font-size:13.5px;color:#a9aed6}.bx input:not([type]){width:100%;background:#000;border:1px solid #2b2f5f;border-radius:6px;color:#fff;padding:8px 10px;font-size:14px;font-family:Consolas,monospace}
.bx{border:1px solid transparent;border-radius:8px}.bx.certo{border-color:#16a34a}.bx.errado{border-color:#ef4444}.st{font-weight:700;text-align:center}
.ops{display:flex;flex-wrap:wrap;gap:6px;padding:2px}.op{background:#11183a;border:1px solid #2b2f5f;border-radius:16px;padding:5px 12px;font-size:13.5px;cursor:pointer;color:#e5e7ff}
.op:has(input:checked){background:#2b1a5c;border-color:#a78bfa}
.bt{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}.dicab{background:transparent;color:#c4b5fd;border:1px dashed #7c3aed;border-radius:8px;padding:8px 14px;font-size:13.5px;cursor:pointer;font-family:inherit}
.dicab.cmdb{border-color:#f5c242;color:#fde68a}.dicab.confirma{background:#3b1d0a;border-style:solid;border-color:#f59e0b;color:#fde68a}
.dt{display:none;margin-top:10px;background:#1a1440;border-left:4px solid #a78bfa;border-radius:6px;padding:10px 12px;font-size:14px;color:#e5e0ff}
.fb{margin-top:10px;font-size:14px;border-radius:6px;padding:10px 12px;display:none}.fb.ok{display:block;background:rgba(22,163,74,.15);border:1px solid #16a34a;color:#bbf7d0}.fb.no{display:block;background:rgba(239,68,68,.12);border:1px solid #ef4444;color:#fecaca}
.fasefim{margin:0 18px 14px;background:linear-gradient(90deg,#14532d,#166534);border-radius:8px;padding:10px 14px;color:#fff;font-weight:600;display:none}
.ptopo{display:flex;justify-content:space-between;align-items:center;gap:10px}.ptit{font-weight:700;color:#fff;font-size:15.5px;cursor:pointer}.ptit input{transform:scale(1.3);margin-right:6px;accent-color:#16a34a}
.passo.feito-ok .ptit{color:#86efac}.chip{background:#2b1a5c;color:#ddd0ff;font-size:12px;border-radius:10px;padding:2px 10px;white-space:nowrap}
.ptxt{margin:6px 0 0;color:#dfe1f3;font-size:14.5px;line-height:1.5}
.barra{height:8px;background:#1a1440;border-radius:6px;overflow:hidden;margin:6px 0 14px}.barra i{display:block;height:100%;width:0;background:linear-gradient(90deg,#7c3aed,#4ade80)}
.regra{background:#11183a;border:1px solid #262a5c;border-radius:10px;padding:12px 16px;font-size:14px;color:#cfd2ea;margin-bottom:12px}
.cmd{display:flex;gap:8px;align-items:stretch;margin-top:6px}.cmd code{flex:1;font-family:Consolas,monospace;font-size:13px;background:#000;color:#c4f0c4;border:1px solid #2b2f5f;border-radius:6px;padding:8px 10px;white-space:pre-wrap;word-break:break-all}
.cmd button{background:#2b1a5c;color:#ddd0ff;border:1px solid #7c3aed;border-radius:6px;padding:0 12px;cursor:pointer;font-size:12.5px}
.cmdl{padding:10px 18px;border-top:1px solid #1d2250}.seq{font-size:13px;font-weight:600;color:#fde68a;margin:4px 0 2px}.ord{display:flex;align-items:center;justify-content:center;min-width:34px;background:#7c3aed;color:#fff;font-weight:700;border-radius:6px;font-size:13px}
.gcmd{padding:10px 18px 4px;font-size:12px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#c4b5fd;border-top:1px solid #262a5c;background:#0d1330}.cmdl p{margin:4px 0 0;font-size:13.5px;color:#a9aed6}
.card{background:#0d1330;border:1px solid #262a5c;border-left:6px solid;border-radius:8px;padding:14px 18px;margin-bottom:14px}
.top{display:flex;gap:12px;align-items:center}.sev{color:#07070c;font-weight:700;font-size:12px;padding:2px 10px;border-radius:10px}
.hora{color:#a9aed6;font-size:13px}.card h3{margin:8px 0 4px;font-size:16px;color:#fff}.card p{margin:0;color:#cfd2ea;font-size:14px;line-height:1.45}
#fundo{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);align-items:center;justify-content:center;z-index:9}
#modal{background:#0d1330;border:1px solid #7c3aed;border-radius:14px;padding:24px 26px;max-width:540px;box-shadow:0 0 50px rgba(124,58,237,.4)}
#modal h3{margin:0 0 10px;font-size:20px;color:#fff}#modal p{margin:0 0 10px;font-size:14.5px}
#modal .acoes{display:flex;gap:10px;justify-content:flex-end;margin-top:16px;flex-wrap:wrap}#modal .mini{font-size:12px;color:#8b90b8;margin-top:12px}
#modal.final{max-width:640px;text-align:center;background:radial-gradient(circle at 50% 0%,#3b1680 0%,#0d1330 60%);border-width:2px}
#modal.final h3{font-size:30px}.escudo{width:84px;height:84px;margin:0 auto 12px;border-radius:50%;background:#16a34a;color:#fff;font-size:46px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 0 10px rgba(74,222,128,.15)}
.sub2{color:#cfd2ea}.kpis{display:flex;gap:10px;justify-content:center;margin:16px 0}.kpis div{background:rgba(0,0,0,.35);border:1px solid #4c1d95;border-radius:10px;padding:10px 16px;min-width:130px}
.kpis b{display:block;font-size:22px;color:#fff}.kpis span{font-size:12px;color:#c4b5fd}
#modal.final ul{text-align:left;margin:0 auto 12px;max-width:520px;color:#dfe1f3;font-size:14px}#modal.final .acoes{justify-content:center}
footer{padding:0 28px 90px;color:#6a6f99;font-size:12px}
.icone{background:rgba(0,0,0,.35);border:1px solid #4c1d95;border-radius:10px;color:#fff;font-size:18px;min-width:46px;cursor:pointer;position:relative}
.icone span{position:absolute;top:-6px;right:-6px;background:#ef4444;color:#fff;font-size:11px;border-radius:10px;padding:1px 6px}
#sinopainel{display:none;position:fixed;top:86px;right:20px;width:380px;max-height:70vh;overflow:auto;background:#0d1330;border:1px solid #7c3aed;border-radius:12px;z-index:8;box-shadow:0 10px 40px rgba(0,0,0,.6)}
.sinocab{padding:10px 14px;font-weight:700;border-bottom:1px solid #262a5c;color:#c4b5fd;text-transform:uppercase;font-size:12px;letter-spacing:.1em}
.notif,.toast{background:#0d1330;border-left:5px solid;padding:10px 14px;border-bottom:1px solid #1d2250}.notif h4,.toast h4{margin:6px 0 2px;font-size:14.5px;color:#fff}.notif p,.toast p{margin:0;font-size:13px;color:#cfd2ea}
#toasts{position:fixed;right:20px;bottom:86px;display:flex;flex-direction:column;gap:10px;z-index:7;width:380px}
.toast{border:1px solid #3b2a7a;border-left:5px solid;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.6);animation:entra .35s ease}.toast.sai{opacity:0;transition:opacity .25s}
.toast .x{margin-left:auto;background:transparent;border:0;color:#a9aed6;cursor:pointer;font-size:14px}
@keyframes entra{from{transform:translateX(40px);opacity:0}to{transform:none;opacity:1}}
#rodape{position:fixed;left:0;right:0;bottom:0;background:#0b1030;border-top:2px solid #262a5c;padding:12px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px;z-index:6}
#rodape.pronto{border-top-color:#16a34a;background:linear-gradient(90deg,#0b1030,#0f2a1a)}#rodtxt{font-size:14px;color:#cfd2ea}
#rodape.pronto #btnfase:not(:disabled){background:#16a34a;box-shadow:0 0 0 4px rgba(74,222,128,.2)}#rodape.pronto #btnfase:not(:disabled):hover{background:#15803d}
#btnfase:disabled{background:#262a5c;color:#6a6f99;cursor:not-allowed}
.ph{color:#fde047;background:rgba(250,204,21,.12);border-bottom:1px dashed #facc15;border-radius:3px;padding:0 2px}
.cmd.preencher code{border-color:#a16207}
.ops.multi{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:6px}.ops.multi .op{border-radius:8px}
#modal.tour{max-width:560px;text-align:left}.tnum{font-size:12px;color:#c4b5fd;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}
.dots{display:flex;gap:6px;margin-top:8px}.dots i{width:9px;height:9px;border-radius:50%;background:#262a5c}.dots i.on{background:#a78bfa}
.escudo.vermelho{background:#b91c1c;box-shadow:0 0 0 10px rgba(239,68,68,.15)}#modal.esgotado{border-color:#ef4444}.passos{text-align:left;color:#dfe1f3;margin:0 auto 12px;max-width:440px}
</style></head><body>
<header><div><div class="brand">TableTop SITALKS</div><h1>Central de Alertas &mdash; TableTop SITALKS</h1><div class="sub">Ativo monitorado: <span class="host">FIN-NB-0423</span> (Ana Souza, Financeiro)</div></div>
<div class="kpis-top"><button class="icone" title="Como funciona" onclick="ajuda()">?</button><button class="icone" title="Notificações do SOC" onclick="sino()">&#128276;<span id="sinonum">0</span></button><div class="kpi" id="relogio"><b id="tempo">45:00</b><small id="tempolbl">tempo restante</small></div><div class="kpi"><b id="pts">0</b><small>pontos</small></div></div></header>
<div class="wrap">
<div class="etapas">$($etapas -join '')</div>
<div class="agora"><b>O que fazer agora</b><p>$(& $enc $e.agora)</p></div>
<div class="tabs"><a href="#desafios" id="tab-desafios" class="ativa" onclick="return irAba(event,'desafios')">Desafios</a><a href="#roteiro" id="tab-roteiro" onclick="return irAba(event,'roteiro')">Roteiro e dicas</a><a href="#comandos" id="tab-comandos" onclick="return irAba(event,'comandos')">Comandos</a><small class="dicaaba">Ctrl + clique abre a aba em outra janela</small></div>
<div class="aba" id="aba-desafios"><div class="regra">Cada resposta certa vale <b>10 pontos</b>. A dica inicial de cada desafio é grátis. No <b>Roteiro</b>, a dica detalhada custa <b>5 pontos</b> e o comando pronto custa <b>10 pontos</b>. <span id="ptsmax"></span></div></div>
<div class="aba" id="aba-roteiro" style="display:none"><div class="regra">Sigam os passos na ordem e marquem cada um ao terminar. Se travarem, comprem uma <b>dica detalhada (&minus;5)</b> ou o <b>comando pronto (&minus;10)</b>: o desconto aparece no placar.</div><div class="sub" id="prog-rot"></div><div class="barra"><i id="bar-rot"></i></div><div id="lista-rot"></div></div>
<div class="aba" id="aba-comandos" style="display:none"><div class="regra">Todos os comandos e ferramentas que a investigação usa. Os comandos rodam no <b>PowerShell</b> (Menu Iniciar &rsaquo; PowerShell). Os trechos em <span class="ph">AMARELO_MAIUSCULO</span> são partes que vocês precisam <b>trocar</b> pelo caminho ou valor certo antes de apertar Enter (ex.: CAMINHO_DO_ARQUIVO vira "`$env:USERPROFILE\Downloads\NF_48213.zip"). Use aspas quando o caminho tiver espaços.</div></div>

</div>
<div id="sinopainel"><div class="sinocab">Notificações do SOC</div><div id="sinolista"></div></div>
<div id="toasts"></div>
<div id="rodape"><div id="rodtxt"></div><button class="btn" id="btnfase" onclick="abrir()" disabled></button></div>
<div id="fundo"><div id="modal"></div></div>
<footer>SIMULAÇÃO DE TREINAMENTO &mdash; domínios .example e IPs de documentação são fictícios. Nova fase liberada? Aperte F5.</footer>
<script type="application/json" id="dados">$dados</script>
<script>$($script:JsPainel)</script>
</body></html>
"@
    Gravar-Texto (Join-Path $Raiz 'Painel_Alertas.html') $html
    Gravar-Texto (Join-Path $Desktop 'Painel de Alertas SOC.html') $html
}

function Criar-Ficha {
    $f = Join-Path $Desktop 'Ficha_da_Equipe.txt'
    if (Test-Path $f) { return }
    $t = @"
FICHA DA EQUIPE  -  TableTop SITALKS  -  Máquina Contaminada
Equipe: ______________________   Líder: ______________________

Os desafios e os campos de resposta estão no Painel de Alertas SOC (Área de Trabalho).
Use esta ficha como rascunho e para montar a apresentação final.

RASCUNHO / ACHADOS
-------------------------------------------------------------------------


LINHA DO TEMPO (para apresentar em 1 minuto)
Hora    | O que aconteceu
--------|----------------------------------------------------------------
        |
        |
        |
        |

DECISÃO DA EQUIPE
Rodar só o antivírus resolve? ____  Por quê? ______________________________
Ações para os próximos 60 min:  1. ____________  2. ____________  3. ____________
Quem avisar: ______________________
"@
    Gravar-Texto $f $t
}

# ---------------------------------------------------------------- limpeza
function Executar-Limpeza {
    Escrever 'Removendo tudo o que a simulação criou nesta VM...' Yellow
    $alvos = @(
        (Join-Path $Downloads 'NF_48213.zip'), (Join-Path $Downloads 'NF_48213'),
        (Join-Path $Downloads 'Relatorio_viagem_set.xlsx.txt'), (Join-Path $Downloads 'Holerite_outubro.pdf.txt'),
        (Join-Path $Desktop 'Caixa_de_Entrada_Ana'), (Join-Path $Desktop 'Evidencias_SOC'),
        (Join-Path $Desktop 'Painel de Alertas SOC.html'), (Join-Path $Desktop 'Ficha_da_Equipe.txt'),
        'C:\ProgramData\SysCache', $Raiz
    )
    foreach ($p in $alvos) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue; Escrever "  removido: $p" DarkGray }
    }
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveUpdate' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'OneDriveSyncHelper' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKCU:\Software\Classes\sitalks' -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($u in 'virus', 'suporte.ti') { if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $u } }
    if ([Diagnostics.EventLog]::Exists($LogNome)) { Remove-EventLog -LogName $LogNome }
    Escrever 'Limpeza concluída. (Se usou snapshot, você também pode simplesmente revertê-lo.)' Green
}

# ================================================================= principal
Banner
try {
    Assert-Ambiente

    if ($Limpar) {
        $ok = Read-Host 'Isso remove todos os artefatos da simulação desta VM. Digite S para confirmar'
        if ($ok -match '^[sS]') { Executar-Limpeza }
        return
    }

    if (-not $Codigo) { $Codigo = Read-Host 'Digite o código da fase informado pelo facilitador' }
    $fase = Abrir-Fase $Codigo
    if (-not $fase) { Escrever 'Código inválido. Confira com o facilitador.' Red; exit 1 }

    $script:EstadoAtual = Ler-Estado
    $n = [int]$fase.fase
    if (@($EstadoAtual.fases) -contains $n) { Escrever "A $($fase.titulo) já foi liberada nesta VM." Yellow; return }
    if ($n -gt 1 -and -not (@($EstadoAtual.fases) -contains ($n - 1))) {
        Escrever "Libere a fase $($n - 1) antes da fase $n." Red; exit 1
    }

    if ($n -gt 1) {
        Escrever ''
        Escrever '  ************************************************' Green
        Escrever ("     FASE {0} CONCLUÍDA. Ótimo trabalho, equipe!" -f ($n - 1)) Green
        Escrever '  ************************************************' Green
        Escrever ''
    }
    Escrever "Liberando: $($fase.titulo)" Cyan
    foreach ($a in $fase.acoes) {
        try {
            switch ($a.tipo) {
                'arquivo'  { Acao-Arquivo $a }
                'anexar'   { Acao-Anexar $a }
                'zip'      { Acao-Zip $a }
                'evento'   { Acao-Evento $a }
                'registro' { Acao-Registro $a }
                'tarefa'   { Acao-Tarefa $a }
                'usuario'  { Acao-Usuario $a }
                'alerta'   { Acao-Alerta $a $EstadoAtual }
                'agora'    { $EstadoAtual.agora = [string]$a.texto }
                'desafios' { $EstadoAtual.desafios = @($EstadoAtual.desafios) + [pscustomobject]@{ fase = [int]$a.fase; json = [string]$a.json } }
            }
        } catch {
            Escrever "   aviso: não foi possível aplicar uma ação ($($a.tipo)): $($_.Exception.Message)" DarkYellow
        }
    }
    if ($n -eq 1) { $EstadoAtual.inicio = (Get-Date).ToString('o') }
    $EstadoAtual.fases = @($EstadoAtual.fases) + $n
    Salvar-Estado $EstadoAtual
    try { Registrar-Protocolo } catch {}
    Gerar-Painel $EstadoAtual
    Start-Process (Join-Path $Desktop 'Painel de Alertas SOC.html') -ErrorAction SilentlyContinue

    Escrever ''
    Escrever "Pistas da $($fase.titulo) liberadas. Bom trabalho, equipe!" Green
    Escrever "PRÓXIMO PASSO: no Painel de Alertas SOC, resolvam os desafios da Fase $n (abas Desafios e Roteiro)." Green
    Escrever 'O Painel de Alertas SOC (Área de Trabalho) mostra os alertas e o que fazer agora.' Green
} catch {
    Escrever "Erro: $($_.Exception.Message)" Red
    exit 1
}
