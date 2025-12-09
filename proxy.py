import socket
import threading
import tldextract
import ipaddress
import select
import argparse

https_f = b"HTTP/1.1 403 Forbidden\r\n\r\n"
https_a = b"HTTP/1.1 200 Connection Established\r\n\r\n"

http_f = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Content-Type: text/html; charset=UTF-8\r\n"
    b"Content-Length: 96\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<html><body><h1>403 Forbidden</h1><p>SITE BARRADO PELO PROXY.</p></body></html>\r\n\r\n"
)

WORDLIST = 'blacklist.txt'
BLACKLIST = open(WORDLIST, 'r').read().splitlines()
BLMODE = True

WILDCARDS = open('wildcards.txt', 'r').read().splitlines()

def block(con):
    print('\033[31mTENTATIVA SUSPEITA BLOQUEADA\033[m')
    try:
        con.send(http_f)
    except:
        pass
    con.close()


def is_wildcard(domain):
    parser = tldextract.extract(domain)
    return parser.suffix in WILDCARDS # Vai bloquear wildcards como o nip.io


def dns_resolve(dom):
    try:
        return socket.gethostbyname(dom) # Resolve o DNS do dominio dado
    except:
        return None


def isloop(ip_d):
    try:
        ip = ipaddress.ip_address(ip_d)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except:
        return True


def get_domain(url):
    parser = tldextract.extract(url)
    return f'{parser.domain}.{parser.suffix}'


def tunnel(client, server):
    sockets = [client, server] # Vamos monitorar 2 sockets com o select abaixo

    try:
        while True:
            # O select aqui vai monitorar os sockets, assim, se algum der erro, a execução não vai travar em um recv()
            # De parametros: Lista de leitura, Lista de escrita, Lista de erros (Se algum der erro ele coloca em e), timeout
            # O timeout vai impedir que sockets fiquem abertos indefinidamente, impedindo ataques que tentem prender recursos do proxy
            # O timeout também impede que a execução trave em algum erro
            r, _, e = select.select(sockets, [], sockets, 10) # r -> Sockets disponiveis para leitura
                                                                           # _ -> Não vamos pegar nenhum para escrita
            if e:                                                          # e -> Sockets com erro
                break

            for src in r: # Percorremos os sockets disponíveis para leitura
                if src is server: # Se o emissor do pacote for o servidor, envia para o cliente
                    dst = client
                else:             # Se o emissor foi o cliente, envia para o servidor
                    dst = server

                try:
                    data = src.recv(4096)
                    if not data:
                        return
                    dst.sendall(data)
                except:
                    return

    finally:
        try:
            client.close()
        except:
            pass
        try:
            server.close()
        except:
            pass

# Aqui eu filtrei, se for HTTPS o navegador envia um CONNECT, e é nesse pacote que analiso
# Se for HTTP, eu verifico os header HOST
def handleconnection(con):
    global BLMODE
    try:
        con.settimeout(10)
        data = con.recv(4096)
    except:
        con.close()
        return

    if not data:
        con.close()
        return

    try:
        text = data.decode()
        lines = text.splitlines()
    except:
        con.close()
        return

    print(lines)

    # =========================================
    # =============== HTTPS ====================
    # =========================================
    if text.startswith('CONNECT'):
        request = text.split(' ')[1]
        host = request.split(':')[0]

        ip = dns_resolve(host)
        if not ip:
            print('\033[31mDNS FALHOU\033[m')
            con.close()
            return

        if isloop(ip): # Sem essa verificação um atacante poderia explorar uma vulnerabilidade chamada SSRF
            print('\033[31mIP DE LOOPBACK DETECTADO\033[m')
            con.close()
            return

        d = get_domain(host)

        if BLMODE:
            if d.lower().strip() in BLACKLIST or is_wildcard(d): # Wildcard aqui são dominios que resolvem para o ip de loopback (SSRF)
                print('\033[31mDOMINIO BLOQUEADO\033[m')
                try:
                    con.send(https_f) # Se o dominio estiver bloqueado, envia um forbidden
                except:
                    pass
                con.close()
                return
        else:
            if d.lower().strip() not in BLACKLIST or is_wildcard(d): # Wildcard aqui são dominios que resolvem para o ip de loopback (SSRF)
                print('\033[31mDOMINIO BLOQUEADO\033[m')             # ou ips de loopback mesmo
                try:
                    con.send(https_f) # Se o dominio estiver bloqueado, envia um forbidden
                except:
                    pass
                con.close()
                return


        try:
            con.send(https_a) # Se não estiver na blacklist, envia a confirmação para o cliente
        except:
            con.close()
            return

        # Nos conectamos ao servidor para abrir o tunel (Porta 443 por padrão)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.settimeout(10)

        try:
            server.connect((ip, 443))
        except:
            print('\033[31mWARNING\033[m Falha ao conectar ao host HTTPS')
            con.close()
            return

        tunnel(con, server) # Então iniciamos o tunel com o cliente e o servidor
        return

    # =========================================
    # ================= HTTP ===================
    # =========================================

    host = None # Só aceitamos conexões que possuam o cabeçalho Host
    for header in lines:
        if header.lower().startswith('host:'):
            host = header.split(':', 1)[1].strip()
            break

    if not host:
        con.close()
        return

    ip = dns_resolve(host)
    if not ip:
        print('\033[31mDNS FALHOU\033[m')
        con.close()
        return

    if isloop(ip):
        print('\033[31mIP DE LOOPBACK DETECTADO\033[m')
        con.close()
        return

    dom = get_domain(host)

    if BLMODE:
        if dom in BLACKLIST or is_wildcard(dom):
            block(con)
            return
    else:
        if dom not in BLACKLIST or is_wildcard(dom):
            block(con)
            return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(10)

    try:
        server.connect((ip, 80))
    except:
        con.close()
        return

    # Envia o primeiro pacote recebido
    try:
        server.sendall(data)
    except:
        con.close()
        server.close()
        return

    # Abre um tunel
    tunnel(con, server)


def receiveconn(s):
    global BLACKLIST
    try:
        while True:
            BLACKLIST = open(WORDLIST, 'r').read().splitlines() # Atualizar a lista de sites bloqueados periodicamente
            try:
                con, client = s.accept()
                print(f'Conexão recebida ---> {client}')
                t = threading.Thread(target=handleconnection, args=(con,)) # Joga a conexão para a função handleconnection
                t.start()

            except Exception as e:
                print("Erro no accept:", e)
    except KeyboardInterrupt:
        print('O USUARIO ESCOLHEU SAIR')
        return

if __name__ == '__main__':
    ip = '0.0.0.0'
    port = 8080

    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', type=str, help='IP que ficará esperando conexões [0.0.0.0 por padrão]')
    parser.add_argument('-p', type=int, help='PORTA onde o proxy ficará "escutando"')
    parser.add_argument('--blacklist', action='store_true', help='Padrão. Define que o proxy filtrará baseado em uma black list')
    parser.add_argument('--whitelist', action='store_true', help='Define filtragem a partir de uma whitelist')
    parser.add_argument('-l', type=str, help='Inclui uma lista personalizada (Será usada de acordo com o modo definido.). O Proxy já aceita a wordlist do github por padrão')
    args = parser.parse_args()

    if args.ip:
        ip = args.ip
    if args.p:
        port = args.p
    if args.whitelist:
        BLMODE = False
    if args.l:
        WORDLIST = args.l
        BLACKLIST = open(args.l, 'r').read().splitlines()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) // Evitar o erro de porta ocupada após reiniciar o proxy
    try:
        s.bind((ip, port))
    except OSError:
        print('Erro: Porta já está em uso')
        exit(0)
    s.listen(200)

    print(f'[+] Escutando em {ip} na porta {port}')
    receiveconn(s)
