						Welcome to the Henkill README file!    

Henkill v1.0
=============

```CIBERSEGURANÇA ``` Esse script é um firewall customizado usando iptables no Linux, com diversas funções para limpar regras, ativar ou desativar proteções, configurar políticas e criar regras avançadas de filtragem de pacotes.    

Compatível com qualquer distro Linux.

![descrição](/henkill.png)  

Instalação
-----------

Atualize sua distro:
 
    $ sudo apt update && sudo apt upgrade && sudo apt dist-upgrade

Verifique se o iptables, git e o make estão instalados:
 
    $ sudo apt install iptables git make

Instale o Henkill:

    $ git clone https://github.com/whoami-a51/henkill.git
    $ cd henkill/
    $ sudo make install
    
Uso
----

Use: ```$ sudo henkill --[argumento]```

Para ver os argumentos válidos:

    $ sudo henkill --help


Desinstalação
--------------

    $ cd henkill/
    $ sudo make uninstall  


Como ele funciona
-----------

🧹 Limpeza de regras (```limparegras``` e ```limpatabelas```)  

&nbsp;&nbsp;&nbsp;&nbsp; • Remove todas as regras existentes no ```iptables``` (chains, counters e políticas).  
&nbsp;&nbsp;&nbsp;&nbsp; • Restaura as políticas padrão para ```ACCEPT``` ou ```DROP```, dependendo do contexto.  

📡 Configuração de ICMP e proteção (```ativaping```, ```ativaprotecao```, ```desativaprotecao```)  

&nbsp;&nbsp;&nbsp;&nbsp; • Habilita ou desabilita respostas a ping (ICMP).  
&nbsp;&nbsp;&nbsp;&nbsp; • Ativa/desativa proteções básicas do kernel contra ataques como:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; • Smurf Attack  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; • SYN Flood   
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; • Redirects  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; • Bogus error responses  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; • Martian packets  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; • Roteamento de pacotes.  

🔐 Configuração de segurança (```politicaspadrao```, ```criachain```, ```dns```)  
	
 &nbsp;&nbsp;&nbsp;&nbsp; • Define políticas padrão ```DROP``` para todas as cadeias (```INPUT```, ```OUTPUT```, ```FORWARD```).  
 &nbsp;&nbsp;&nbsp;&nbsp; • Cria duas chains personalizadas:  
 
	SYN → combate SYN Flood  
	SCANNER → combate port scans  

&nbsp;&nbsp;&nbsp;&nbsp; • Usa regras baseadas em ```recent``` para detectar e bloquear ataques reincidentes.  
&nbsp;&nbsp;&nbsp;&nbsp; • Ativa logs de tentativas de acesso a portas sensíveis (20, 21, 22, 23 — FTP, SSH, Telnet).  

🔁 Loopback e conexões estabelecidas (```permitirloop```)  

&nbsp;&nbsp;&nbsp;&nbsp; • Permite tráfego do ```lo``` (loopback).  
&nbsp;&nbsp;&nbsp;&nbsp; • Permite conexões estabelecidas ou relacionadas, o coração de qualquer firewall funcional.  

🌐 DNS e serviços externos (```dns```)  

&nbsp;&nbsp;&nbsp;&nbsp; • Libera tráfego DNS de entrada vindo da porta 53.  
&nbsp;&nbsp;&nbsp;&nbsp; • (Comentado) Exemplo de como liberar outras portas para serviços comuns (HTTP, HTTPS, etc).  


⚠️ Algumas observações:  

&nbsp;&nbsp;&nbsp;&nbsp; • É um firewall bem agressivo, bloqueando quase tudo por padrão.  
&nbsp;&nbsp;&nbsp;&nbsp; • ICMP é desativado por padrão, então comandos como ```ping``` vão parar de funcionar, o que pode ser problemático em redes que  
&nbsp;&nbsp;&nbsp;&nbsp; precisam de diagnóstico.  
&nbsp;&nbsp;&nbsp;&nbsp; • Algumas portas são explicitamente bloqueadas mesmo depois de logadas.   
&nbsp;&nbsp;&nbsp;&nbsp; • Pode prejudicar serviços legítimos se não for bem ajustado.  
    
