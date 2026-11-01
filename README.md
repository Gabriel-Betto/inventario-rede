# inventario-rede

Ferramenta em Python (só biblioteca padrão) que cruza **três fontes** de uma rede local e mostra o que está em uso, o que está livre e o que está errado:

- **Tabela ARP** (`arp -a` no Windows, `arp -an` ou `ip neigh` no Linux): quem está respondendo agora.
- **Leases do DHCP** (`dhcpd.leases`, formato ISC, o usado pelo pfSense): quem recebeu IP automático.
- **Lista de IPs estáticos** (CSV): o que está documentado como fixo.

> Todos os dados em `data/` são **fictícios**, feitos só para exemplo.

## O que ela entrega

| Arquivo | Conteúdo |
|---|---|
| `inventario.csv` | Um dispositivo por IP: tipo (Estático / DHCP / Só ARP), MAC, hostname, fontes onde apareceu |
| `conflitos.csv` | Problemas encontrados, por gravidade (ALTA, MÉDIA, INFO) |
| `ips_livres.csv` | IPs livres da rede informada, separados em "Pool DHCP" e "Fora do pool" (bons para novos IPs fixos) |
| `inventario_rede.xlsx` | Tudo em abas (opcional, precisa de `openpyxl`) |

### Problemas detectados

- **ALTA** – IP com MACs diferentes (possível conflito de IP); IP estático duplicado na lista.
- **MÉDIA** – IP estático dentro do pool DHCP; MAC com mais de um IP; dispositivo na rede sem registro.
- **INFO** – IP estático documentado mas sem atividade.

"Sem registro" e "sem atividade" só aparecem quando há outra fonte para comparar (ex.: ARP + lista de estáticos).

## Requisitos

- Python 3.9 ou superior
- Opcional: `pip install openpyxl` (só para `--xlsx`)

## Como usar

### 1. Coletar os dados

Windows (PowerShell). O `>` do PowerShell 5.1 grava em UTF-16; o programa lê isso normalmente:

```powershell
arp -a > arp.txt
```

Linux:

```bash
arp -an > arp.txt        # ou: ip neigh > arp.txt
```

Leases do pfSense: copie o arquivo `/var/dhcpd/var/db/dhcpd.leases` (Diagnostics > Edit File, ou via SCP). Kea não é suportado.

Estáticos: um CSV com cabeçalho `ip;mac;hostname;descricao` (veja `data/estaticos_exemplo.csv`). `;` ou `,` são detectados sozinhos. O MAC pode ficar vazio.

### 2. Rodar

```bash
python -m inventario_rede \
  --arp arp.txt \
  --dhcp dhcpd.leases \
  --estaticos estaticos.csv \
  --rede 192.168.10.0/24 \
  --pool 192.168.10.100-192.168.10.200 \
  --reservar 192.168.10.2 \
  --saida saida
```

Com os dados de exemplo:

```bash
python -m inventario_rede \
  --arp data/arp_windows_exemplo.txt data/arp_linux_exemplo.txt \
  --dhcp data/dhcpd_leases_exemplo.txt \
  --estaticos data/estaticos_exemplo.csv \
  --rede 192.168.10.0/24 --pool 192.168.10.100-192.168.10.200
```

### Opções

| Opção | Função |
|---|---|
| `--arp ARQ [ARQ...]` | Um ou mais arquivos de ARP |
| `--dhcp ARQ` | `dhcpd.leases` |
| `--estaticos ARQ` | CSV de IPs estáticos |
| `--rede CIDR` | Calcula IPs livres (mínimo /16) |
| `--pool INI-FIM` | Faixa do DHCP, para separar livres e detectar estático dentro dela |
| `--reservar IP [IP...]` | IPs a tirar da lista de livres |
| `--saida PASTA` | Pasta de saída (padrão `saida`) |
| `--sep` | Separador do CSV (padrão `;`, abre direto no Excel pt-BR) |
| `--xlsx` | Gera também o Excel |
| `--validar-expiracao` | Ignora leases já vencidos |
| `--falhar-se-conflito` | Sai com código 2 se houver problema de gravidade ALTA (útil em rotina/agendador) |

Códigos de saída: `0` ok, `1` erro de uso/arquivo, `2` conflito de gravidade ALTA (com `--falhar-se-conflito`).

## Decisões de projeto

- No `dhcpd.leases` o arquivo só cresce; por isso, **vale o último bloco de cada IP** e só entram leases com `binding state active`.
- ARP ignora multicast, broadcast, MAC zerado e entradas `<incomplete>`.
- Os arquivos podem estar em UTF-8, UTF-8 com BOM, UTF-16 ou cp1252.
- CSV gravado em `utf-8-sig` com `;` para o Excel brasileiro abrir os acentos corretamente.
- Redes maiores que /16 são recusadas para não gerar milhões de linhas por engano.

## Testes

```bash
python -m unittest discover -s tests -v
```

Cobrem os parsers (Windows, Linux, `ip neigh`, DHCP, CSV), codificações, cada tipo de conflito, cálculo de IPs livres e o fluxo completo da linha de comando, incluindo códigos de saída.

## Limitações

- ARP mostra só o que a máquina que rodou o comando viu recentemente: rode de mais de um ponto ou depois de um `ping` na faixa para melhorar a cobertura.
- Não faz varredura de rede nem consulta o fabricante pelo MAC.
- Só lê o formato ISC do DHCP.

## Licença

MIT, veja `LICENSE`.
