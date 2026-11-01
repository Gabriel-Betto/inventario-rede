"""Testes do inventario-rede. Rodar com:  python -m unittest discover -s tests -v"""

import csv
import ipaddress
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from inventario_rede import analise, cli, parsers
from inventario_rede.parsers import ORIGEM_ARP, ORIGEM_DHCP, ORIGEM_ESTATICO, Registro

RAIZ = Path(__file__).resolve().parent.parent
DADOS = RAIZ / "data"


class TestMac(unittest.TestCase):
    def test_normaliza_formatos(self):
        self.assertEqual(parsers.normalizar_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsers.normalizar_mac(" aa:bb:cc:dd:ee:ff "), "aa:bb:cc:dd:ee:ff")

    def test_rejeita_invalidos(self):
        for texto in ["", "zz:zz:zz", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "aabbccddeeff"]:
            self.assertIsNone(parsers.normalizar_mac(texto), texto)

    def test_mac_de_dispositivo(self):
        self.assertTrue(parsers.mac_de_dispositivo("3c:52:82:15:00:50"))
        self.assertFalse(parsers.mac_de_dispositivo("ff:ff:ff:ff:ff:ff"))  # broadcast
        self.assertFalse(parsers.mac_de_dispositivo("01:00:5e:00:00:16"))  # multicast
        self.assertFalse(parsers.mac_de_dispositivo("00:00:00:00:00:00"))


class TestArp(unittest.TestCase):
    def test_windows(self):
        texto = (
            "Interface: 192.168.10.50 --- 0x4\n"
            "  Endereço IP           Endereço físico       Tipo\n"
            "  192.168.10.1          00-0c-29-aa-00-01     dinâmico\n"
            "  192.168.10.255        ff-ff-ff-ff-ff-ff     estático\n"
            "  224.0.0.22            01-00-5e-00-00-16     estático\n"
        )
        regs = parsers.parse_arp(texto)
        self.assertEqual([(r.ip, r.mac) for r in regs], [("192.168.10.1", "00:0c:29:aa:00:01")])

    def test_linux_arp_an(self):
        texto = (
            "gateway (192.168.10.1) at 00:0c:29:aa:00:01 [ether] on eth0\n"
            "? (192.168.10.153) at <incomplete> on eth0\n"
        )
        regs = parsers.parse_arp(texto)
        self.assertEqual([(r.ip, r.mac) for r in regs], [("192.168.10.1", "00:0c:29:aa:00:01")])

    def test_ip_neigh(self):
        texto = (
            "192.168.10.1 dev eth0 lladdr 00:0c:29:aa:00:01 REACHABLE\n"
            "192.168.10.9 dev eth0  FAILED\n"
        )
        regs = parsers.parse_arp(texto)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].origem, ORIGEM_ARP)

    def test_remove_repetidos(self):
        linha = "192.168.10.1 00-0c-29-aa-00-01 dinâmico\n"
        self.assertEqual(len(parsers.parse_arp(linha * 3)), 1)

    def test_texto_vazio_ou_lixo(self):
        self.assertEqual(parsers.parse_arp(""), [])
        self.assertEqual(parsers.parse_arp("nada de útil aqui\n999.1.1.1 00-0c-29-aa-00-01"), [])


LEASES = """
lease 10.0.0.5 {
  binding state active;
  hardware ethernet AA:BB:CC:00:00:05;
  client-hostname "pc-05";
  ends 3 2026/10/28 14:00:00;
}
lease 10.0.0.6 {
  binding state active;
  hardware ethernet aa:bb:cc:00:00:06;
}
lease 10.0.0.6 {
  binding state free;
  hardware ethernet aa:bb:cc:00:00:06;
}
lease 10.0.0.7 {
  binding state active;
  next binding state free;
}
lease 10.0.0.8 {
  binding state active;
  hardware ethernet aa:bb:cc:00:00:08;
  ends never;
}
"""


class TestDhcp(unittest.TestCase):
    def test_ultimo_bloco_vale_e_so_ativos(self):
        regs = {r.ip: r for r in parsers.parse_dhcp_leases(LEASES)}
        self.assertIn("10.0.0.5", regs)
        self.assertNotIn("10.0.0.6", regs, "o último bloco do 10.0.0.6 é 'free'")
        self.assertNotIn("10.0.0.7", regs, "lease sem MAC não entra")
        self.assertEqual(regs["10.0.0.5"].hostname, "pc-05")
        self.assertEqual(regs["10.0.0.5"].mac, "aa:bb:cc:00:00:05")
        self.assertEqual(regs["10.0.0.5"].origem, ORIGEM_DHCP)

    def test_validacao_de_expiracao(self):
        depois = datetime(2026, 10, 29)
        antes = datetime(2026, 10, 28, 12, 0, 0)
        sem = {r.ip for r in parsers.parse_dhcp_leases(LEASES)}
        com_expirado = {r.ip for r in parsers.parse_dhcp_leases(LEASES, True, depois)}
        com_valido = {r.ip for r in parsers.parse_dhcp_leases(LEASES, True, antes)}
        self.assertIn("10.0.0.5", sem)
        self.assertNotIn("10.0.0.5", com_expirado)
        self.assertIn("10.0.0.5", com_valido)
        self.assertIn("10.0.0.8", com_expirado, "'ends never' nunca expira")


class TestEstaticos(unittest.TestCase):
    def test_ponto_e_virgula_e_aviso(self):
        texto = "ip;mac;hostname;descricao\n10.0.0.1;AA-BB-CC-00-00-01;fw;Firewall\n10.0.0.2;zz;sw;ruim\nabc;;x;y\n"
        regs, avisos = parsers.parse_estaticos(texto)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0].mac, "aa:bb:cc:00:00:01")
        self.assertEqual(regs[0].origem, ORIGEM_ESTATICO)
        self.assertEqual(len(avisos), 2)
        self.assertIn("linha 3", avisos[0])
        self.assertIn("linha 4", avisos[1])

    def test_virgula_bom_e_nome(self):
        texto = "﻿IP,MAC,Nome\n10.0.0.1,,fw\n"
        regs, avisos = parsers.parse_estaticos(texto)
        self.assertEqual([(r.ip, r.mac, r.hostname) for r in regs], [("10.0.0.1", "", "fw")])
        self.assertEqual(avisos, [])

    def test_sem_coluna_ip(self):
        regs, avisos = parsers.parse_estaticos("mac;nome\naa:bb:cc:00:00:01;x\n")
        self.assertEqual(regs, [])
        self.assertTrue(avisos)

    def test_vazio(self):
        self.assertEqual(parsers.parse_estaticos("  \n\n"), ([], []))


class TestLerTexto(unittest.TestCase):
    def test_codificacoes(self):
        conteudo = "192.168.10.1 00-0c-29-aa-00-01 dinâmico"
        with tempfile.TemporaryDirectory() as tmp:
            for nome, dados in {
                "utf8.txt": conteudo.encode("utf-8"),
                "utf8bom.txt": b"\xef\xbb\xbf" + conteudo.encode("utf-8"),
                "utf16.txt": conteudo.encode("utf-16"),  # como o PowerShell 5.1 grava com '>'
                "cp1252.txt": conteudo.encode("cp1252"),
            }.items():
                caminho = Path(tmp) / nome
                caminho.write_bytes(dados)
                regs = parsers.parse_arp(parsers.ler_texto(caminho))
                self.assertEqual(len(regs), 1, nome)


def reg(ip, mac, origem, nome=""):
    return Registro(ip=ip, mac=mac, origem=origem, hostname=nome)


class TestAnalise(unittest.TestCase):
    def test_consolidar_ordena_numericamente(self):
        regs = [reg("10.0.0.10", "aa:aa:aa:aa:aa:01", ORIGEM_ARP), reg("10.0.0.9", "aa:aa:aa:aa:aa:02", ORIGEM_DHCP, "x")]
        self.assertEqual([d.ip for d in analise.consolidar(regs)], ["10.0.0.9", "10.0.0.10"])

    def test_tipo_e_fontes(self):
        regs = [reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ESTATICO), reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ARP)]
        (d,) = analise.consolidar(regs)
        self.assertEqual(d.tipo, "Estático")
        self.assertEqual(d.fontes, "Estático + ARP")

    def tipos(self, conflitos):
        return {(c.tipo, c.alvo) for c in conflitos}

    def test_ip_com_macs_diferentes(self):
        regs = [reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ESTATICO), reg("10.0.0.1", "aa:aa:aa:aa:aa:02", ORIGEM_ARP)]
        achados = analise.achar_conflitos(regs, {ORIGEM_ARP, ORIGEM_ESTATICO})
        self.assertIn(("IP com MACs diferentes", "10.0.0.1"), self.tipos(achados))
        self.assertEqual(achados[0].gravidade, "ALTA")

    def test_estatico_duplicado(self):
        regs = [reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ESTATICO), reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ESTATICO)]
        achados = analise.achar_conflitos(regs, {ORIGEM_ESTATICO})
        self.assertIn(("IP estático duplicado", "10.0.0.1"), self.tipos(achados))

    def test_estatico_no_pool(self):
        pool = analise.parse_pool("10.0.0.100-10.0.0.200")
        regs = [reg("10.0.0.150", "aa:aa:aa:aa:aa:01", ORIGEM_ESTATICO), reg("10.0.0.5", "aa:aa:aa:aa:aa:02", ORIGEM_ESTATICO)]
        achados = analise.achar_conflitos(regs, {ORIGEM_ESTATICO}, pool)
        self.assertIn(("IP estático dentro do pool DHCP", "10.0.0.150"), self.tipos(achados))
        self.assertNotIn(("IP estático dentro do pool DHCP", "10.0.0.5"), self.tipos(achados))

    def test_mac_com_varios_ips(self):
        regs = [reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_DHCP), reg("10.0.0.2", "aa:aa:aa:aa:aa:01", ORIGEM_ARP)]
        achados = analise.achar_conflitos(regs, {ORIGEM_ARP, ORIGEM_DHCP})
        self.assertIn(("MAC com mais de um IP", "aa:aa:aa:aa:aa:01"), self.tipos(achados))

    def test_dispositivo_sem_registro_so_com_fonte_de_comparacao(self):
        regs = [reg("10.0.0.9", "aa:aa:aa:aa:aa:09", ORIGEM_ARP)]
        so_arp = analise.achar_conflitos(regs, {ORIGEM_ARP})
        self.assertEqual(so_arp, [], "sozinho, o ARP não tem com o que ser comparado")
        com_dhcp = analise.achar_conflitos(regs, {ORIGEM_ARP, ORIGEM_DHCP})
        self.assertIn(("Dispositivo sem registro", "10.0.0.9"), self.tipos(com_dhcp))

    def test_estatico_sem_atividade_so_com_arp_ou_dhcp(self):
        regs = [reg("10.0.0.21", "aa:aa:aa:aa:aa:21", ORIGEM_ESTATICO)]
        self.assertEqual(analise.achar_conflitos(regs, {ORIGEM_ESTATICO}), [])
        achados = analise.achar_conflitos(regs, {ORIGEM_ESTATICO, ORIGEM_ARP})
        self.assertIn(("Estático sem atividade", "10.0.0.21"), self.tipos(achados))
        self.assertEqual(achados[0].gravidade, "INFO")

    def test_ordenacao_por_gravidade(self):
        regs = [
            reg("10.0.0.21", "aa:aa:aa:aa:aa:21", ORIGEM_ESTATICO),
            reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ESTATICO),
            reg("10.0.0.1", "aa:aa:aa:aa:aa:02", ORIGEM_ARP),
        ]
        gravidades = [c.gravidade for c in analise.achar_conflitos(regs, {ORIGEM_ESTATICO, ORIGEM_ARP})]
        self.assertEqual(gravidades, sorted(gravidades, key=lambda g: analise.GRAVIDADES[g]))

    def test_sem_conflitos(self):
        regs = [reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ESTATICO), reg("10.0.0.1", "aa:aa:aa:aa:aa:01", ORIGEM_ARP)]
        self.assertEqual(analise.achar_conflitos(regs, {ORIGEM_ESTATICO, ORIGEM_ARP}), [])


class TestIpsLivres(unittest.TestCase):
    def test_exclui_usados_reservados_rede_e_broadcast(self):
        rede = ipaddress.ip_network("10.0.0.0/29")  # hosts .1 a .6
        livres = analise.ips_livres(rede, ["10.0.0.1"], ["10.0.0.2"])
        self.assertEqual([ip for ip, _ in livres], ["10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"])

    def test_zonas_do_pool(self):
        rede = ipaddress.ip_network("10.0.0.0/29")
        pool = analise.parse_pool("10.0.0.4-10.0.0.6")
        zonas = dict(analise.ips_livres(rede, [], [], pool))
        self.assertEqual(zonas["10.0.0.3"], "Fora do pool")
        self.assertEqual(zonas["10.0.0.4"], "Pool DHCP")
        self.assertEqual(zonas["10.0.0.6"], "Pool DHCP")

    def test_rede_grande_demais(self):
        with self.assertRaises(ValueError):
            analise.ips_livres(ipaddress.ip_network("10.0.0.0/8"), [])

    def test_pool_invalido(self):
        for texto in ["10.0.0.5", "10.0.0.9-10.0.0.1", "a-b", "10.0.0.1-10.0.0.2-10.0.0.3"]:
            with self.assertRaises(ValueError, msg=texto):
                analise.parse_pool(texto)


class TestCli(unittest.TestCase):
    def rodar(self, *extra, saida=None):
        args = [
            "--arp", str(DADOS / "arp_windows_exemplo.txt"), str(DADOS / "arp_linux_exemplo.txt"),
            "--dhcp", str(DADOS / "dhcpd_leases_exemplo.txt"),
            "--estaticos", str(DADOS / "estaticos_exemplo.csv"),
            "--rede", "192.168.10.0/24", "--pool", "192.168.10.100-192.168.10.200",
            "--saida", str(saida),
        ] + list(extra)
        return cli.main(args)

    def ler_csv(self, caminho):
        with open(caminho, encoding="utf-8-sig", newline="") as arq:
            return list(csv.DictReader(arq, delimiter=";"))

    def test_fim_a_fim_com_dados_de_exemplo(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.rodar(saida=tmp), 0)
            inv = {l["IP"]: l for l in self.ler_csv(Path(tmp) / "inventario.csv")}
            self.assertEqual(len(inv), 11)
            self.assertEqual(inv["192.168.10.150"]["Hostname"], "pc-vendas-01")
            self.assertEqual(inv["192.168.10.77"]["Tipo"], "Só ARP")
            self.assertNotIn("192.168.10.160", inv, "lease 'free' não pode entrar")
            self.assertNotIn("192.168.10.255", inv, "broadcast não é dispositivo")
            self.assertNotIn("192.168.10.30", inv, "estático com MAC inválido é ignorado")

            problemas = self.ler_csv(Path(tmp) / "conflitos.csv")
            self.assertEqual(
                {(p["Problema"], p["Alvo"]) for p in problemas},
                {
                    ("IP com MACs diferentes", "192.168.10.20"),
                    ("Dispositivo sem registro", "192.168.10.77"),
                    ("Dispositivo sem registro", "192.168.10.152"),
                    ("IP estático dentro do pool DHCP", "192.168.10.120"),
                    ("MAC com mais de um IP", "3c:52:82:15:00:51"),
                    ("Estático sem atividade", "192.168.10.21"),
                },
            )
            livres = self.ler_csv(Path(tmp) / "ips_livres.csv")
            ips_livres = {l["IP"] for l in livres}
            self.assertEqual(len(livres), 254 - 11)
            self.assertNotIn("192.168.10.1", ips_livres)
            self.assertIn("192.168.10.2", ips_livres)

    def test_reservar_tira_ip_dos_livres(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.rodar("--reservar", "192.168.10.2", saida=tmp)
            livres = {l["IP"] for l in self.ler_csv(Path(tmp) / "ips_livres.csv")}
            self.assertNotIn("192.168.10.2", livres)

    def test_falhar_se_conflito(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.rodar("--falhar-se-conflito", saida=tmp), 2)

    def test_sem_conflito_alto_retorna_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            codigo = cli.main(["--estaticos", str(DADOS / "estaticos_exemplo.csv"), "--falhar-se-conflito", "--saida", tmp])
            self.assertEqual(codigo, 0)

    def test_separador_virgula(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.rodar("--sep", ",", saida=tmp)
            cabecalho = (Path(tmp) / "inventario.csv").read_text(encoding="utf-8-sig").splitlines()[0]
            self.assertTrue(cabecalho.startswith("IP,Tipo,MAC"))

    def test_xlsx(self):
        try:
            import openpyxl
        except ImportError:
            self.skipTest("openpyxl não instalado")
        with tempfile.TemporaryDirectory() as tmp:
            self.rodar("--xlsx", saida=tmp)
            livro = openpyxl.load_workbook(Path(tmp) / "inventario_rede.xlsx")
            self.assertEqual(livro.sheetnames, ["Inventário", "Conflitos", "IPs livres"])
            self.assertEqual(livro["Inventário"].max_row, 12)  # cabeçalho + 11

    def test_erros_de_uso(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(cli.main(["--saida", tmp]), 1, "sem nenhuma fonte")
            self.assertEqual(cli.main(["--estaticos", str(DADOS / "nao_existe.csv"), "--saida", tmp]), 1)
            self.assertEqual(cli.main(["--estaticos", str(DADOS / "estaticos_exemplo.csv"), "--rede", "abc", "--saida", tmp]), 1)
            self.assertEqual(cli.main(["--estaticos", str(DADOS / "estaticos_exemplo.csv"), "--rede", "10.0.0.0/8", "--saida", tmp]), 1)
            self.assertEqual(cli.main(["--estaticos", str(DADOS / "estaticos_exemplo.csv"), "--pool", "x", "--saida", tmp]), 1)


if __name__ == "__main__":
    unittest.main()
