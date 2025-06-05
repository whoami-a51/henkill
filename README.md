						Welcome to the Henkill README file!    

Henkill v1.0
=============

Esse script é um firewall customizado usando iptables no Linux, com diversas funções para limpar regras, ativar ou desativar proteções, configurar políticas e criar regras avançadas de filtragem de pacotes.   

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


🧹 Limpeza de regras (```limparegras``` e ```limpatabelas```)  

   • Remove todas as regras existentes no ```iptables``` (chains, counters e políticas).  

   • Restaura as políticas padrão para ```ACCEPT``` ou ```DROP```, dependendo do contexto.  

📡 Configuração de ICMP e proteção (```ativaping```, ```ativaprotecao```, ```desativaprotecao```)  

   • Habilita ou desabilita respostas a ping (ICMP).  

   • Ativa/desativa proteções básicas do kernel contra ataques como:  
	• Smurf Attack  
	• SYN Flood   
	• Redirects  
	• Bogus error responses  
 	• Martian packets  
	• Roteamento de pacotes.  

🔐 Configuração de segurança (```politicaspadrao```, ```criachain```, ```dns```)  
	
   • Define políticas padrão ```DROP``` para todas as cadeias (```INPUT```, ```OUTPUT```, ```FORWARD```).  
   • Cria duas chains personalizadas:  
 
	SYN → combate SYN Flood  

	SCANNER → combate port scans  

   • Usa regras baseadas em ```recent``` para detectar e bloquear ataques reincidentes.  

   • Ativa logs de tentativas de acesso a portas sensíveis (20, 21, 22, 23 — FTP, SSH, Telnet).  

🔁 Loopback e conexões estabelecidas (```permitirloop```)  

   • Permite tráfego do ```lo``` (loopback).  

   • Permite conexões estabelecidas ou relacionadas, o coração de qualquer firewall funcional.  

🌐 DNS e serviços externos (```dns```)  

   • Libera tráfego DNS de entrada vindo da porta 53.  

   • (Comentado) Exemplo de como liberar outras portas para serviços comuns (HTTP, HTTPS, etc).  


⚠️ Algumas observações:  

   • É um firewall bem agressivo, bloqueando quase tudo por padrão.  

   • ICMP é desativado por padrão, então comandos como ```ping``` vão parar de funcionar, o que pode ser problemático em redes que precisam de diagnóstico.  

   • Algumas portas são explicitamente bloqueadas mesmo depois de logadas.   

   • Pode prejudicar serviços legítimos se não for bem ajustado.  
    
