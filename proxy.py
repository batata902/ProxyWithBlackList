import socket
import threading
import tldextract

http_forbidden = ("HTTP/1.1 403 Forbidden\r\n"
             "Content-Type: text/html; charset=utf-8\r\n"
             "Connection: close\r\n\r\n"
             "<h1>403 Forbidden</h1>"
             "<p>ESSE SITE ESTÁ BLOQUEADO.</p>")
https_forbidden = ("HTTP/1.1 403 Forbidden\r\n"
                   "Connection: close\r\n\r\n")
https_success = b"HTTP/1.1 200 Connection Established\r\n\r\n"

blacklist = open('blockedWebsites.txt', 'r').read().splitlines()
lock = threading.Lock()


def getdomain(domain):
    parse = tldextract.extract(domain)
    dominio = f"{parse.domain}.{parse.suffix}"
    return dominio


def tunnel(con1, con2):
    def forward(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
            src.close()
            dst.close()
        except:
            pass
        finally:
            src.close()
            dst.close()
        return
    t1 = threading.Thread(target=forward, args=(con1, con2,))
    t2 = threading.Thread(target=forward, args=(con2, con1,))
    t1.start()
    t2.start()



def verificacao(con):
    try:
        request = con.recv(1024).decode().splitlines()
        dominio = request[0].split(' ')[1]
        porta = 80
        print(request)

        # HANDLE HTTPS REQUEST
        if request[0].split(' ')[0] == 'CONNECT':
            porta = int(dominio.split(':')[1])
            dominio = dominio.split(':')[0]
            if dominio in blacklist:
                print('Site bloqueado!')
                con.sendall(https_forbidden.encode())
                con.close()
                return
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect((dominio, porta))
            con.sendall(https_success)

            tunnel(con, server)
            return

        # HANDLE HTTP REQUEST
        dominio = getdomain(dominio)

        if dominio in blacklist:
            print('Site bloqueado!')
            con.sendall(http_forbidden.encode())
            con.close()
            return
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((dominio, porta))
        request = '\r\n'.join(request) + '\r\n\r\n'
        server.sendall(request.encode())
        tunnel(con, server)
        return
    except Exception as error:
        print(error)
        con.close()
        return


def handleConn(s):
    while True:
        con, client = s.accept()
        print(f'[INFO] Cliente conectado --> {client}')
        t = threading.Thread(target=verificacao, args=(con,))
        t.start()



if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 8080))
    s.listen(100)
    print('[+] proxy ativo em 0.0.0.0 na porta 8080...')
    handleConn(s)
