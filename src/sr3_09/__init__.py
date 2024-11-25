# !!!!!!!!!
# Repo git: https://github.com/UHA-2301242/SR3.09
# !!!!!!!!!

import ipaddress
import socket
import sys
import threading
import typing

from PyQt6.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QWidget,
)


class Infos(typing.TypedDict):
    serv: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int
    max_clients: int


class App(QWidget):
    def __init__(self):
        super().__init__()

        self.clients: list[threading.Thread] = []

        self.serv_req = QLineEdit("127.0.0.1")  # Localhost
        self.port_req = QLineEdit("4200")
        self.max_clients_req = QLineEdit("5")
        self.inputs = [self.serv_req, self.port_req, self.max_clients_req]

        self.start_serv_btn = QPushButton("Démarrer le serveur")
        self.socket: socket.socket | None = None

        self.text_box = QTextEdit()

        self.currently_accept = False

        self.accepting_thread: threading.Thread | None = None
        self.init_ui()

    def init_ui(self):
        grid = QGridLayout()
        self.setLayout(grid)

        serv_req = QHBoxLayout()
        port_req = QHBoxLayout()
        max_clients_req = QHBoxLayout()

        serv_req.addWidget(QLabel("IP :"))
        serv_req.addWidget(self.serv_req)
        port_req.addWidget(QLabel("Port :"))
        port_req.addWidget(self.port_req)
        max_clients_req.addWidget(QLabel("Nombre max de clients :"))
        max_clients_req.addWidget(self.max_clients_req)

        grid.addLayout(serv_req, 0, 0)
        grid.addLayout(port_req, 1, 0)
        grid.addLayout(max_clients_req, 2, 0)

        self.start_serv_btn.clicked.connect(self.create_server)
        grid.addWidget(self.start_serv_btn, 3, 0, 1, 2)

        grid.addWidget(self.text_box, 4, 0, 1, 2)

        self.show()

    def error_message(self, message: str):
        """Affiche un message d'erreur"""
        QMessageBox.information(self, "Error", message)

    def get_current_infos(self) -> Infos:
        """Obtiens les infos. Retourne "ValueError" en cas de valeur incorrecte, avec un message."""
        try:
            ip = self.serv_req.text()
            ip = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("Veuillez entrer une adresse IP valide")
        try:
            port = self.port_req.text()
            port = int(port)
        except ValueError:
            raise ValueError("Veuillez entrer un port valide")
        try:
            max_clients = self.max_clients_req.text()
            max_clients = int(max_clients)
        except ValueError:
            raise ValueError("Veuillez entrer un nombre de clients valide")
        return Infos(serv=ip, port=port, max_clients=max_clients)

    def create_server(self):
        """Commence la création du serveur en mettant à jour l'UI"""
        try:
            info = self.get_current_infos()
        except ValueError as why:
            return self.error_message(str(why))

        if self.currently_accept:
            # Déjà actif ? On stop tout alors
            self.__stop()
            self.start_serv_btn.setText("Démarrer le serveur")
            for item in self.inputs:
                item.setReadOnly(False)
        else:
            # Si le serveur n'est pas actif, on démarre le serveur
            try:
                self.__demarrage()
            except OSError:
                return self.error_message("Erreur lors de l'ouverture du serveur. Port déjà en usage ?")

            self.start_serv_btn.setText("Arrêter le serveur")
            for item in self.inputs:
                item.setReadOnly(True)


        self.currently_accept = not self.currently_accept

        self.accepting_thread = threading.Thread(target=self.__accept)
        self.accepting_thread.start()

    def __demarrage(self):
        infos = self.get_current_infos()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.socket.bind((str(infos["serv"]), infos["port"]))
        self.socket.listen(infos["max_clients"])

        print(
            f"Serveur démarré sur {infos['serv']}:{infos['port']} (Max clients : {infos['max_clients']})"
        )

    def __accept(self):
        if not self.socket:
            print("Attention ! Aucun socket ouvert trouvé...")
            return

        try:
            print("En attente d'un client...")
            client_socket, _ = self.socket.accept()
            thread = threading.Thread(
                target=self.__receive_message_from_client, args=(client_socket,)
            )
            thread.start()

            self.clients.append(thread)

        except Exception as error:
            print(f"Erreur lors de la relation avec un client : {error}")

    def __receive_message_from_client(self, client_socket: socket.socket):
        while True:
            message = client_socket.recv(1024)
            if message == b"":
                break
            message_decoded = message.decode('utf-8')
            if message_decoded == "deco-server":
                client_socket.close()
                self.text_box.append("! Déconnexion du port {client_socket.getpeername()[1]")
                break
            
            self.text_box.append(
                f"> Port {client_socket.getpeername()[1]} : {message_decoded}"
            )

    def __stop(self):
        if self.socket:
            self.socket.close()
            if self.accepting_thread:
                self.accepting_thread
            self.socket = None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = App()
    try:
        sys.exit(app.exec())
    finally:
        if ex.socket:
            ex.socket.close()
