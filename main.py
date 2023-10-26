from tkinter import *
from scapy.all import *
from scapy.layers.inet import IP

# Fonction pour l'analyse et la mise à jour du tableau de bord
def analyze_packet(packet):
    # Analyse du paquet - exemple : identifier le protocole
    if IP in packet:
        if packet[IP].proto == 6:
            protocol = "TCP"
        elif packet[IP].proto == 17:
            protocol = "UDP"
        else:
            protocol = "Autre"
    else:
        protocol = "Non-IP"

    # Mise à jour du tableau de bord en temps réel
    text.insert(END, f"Paquet {protocol}\n")
    text.see(END)  # Faites défiler le texte pour afficher le dernier paquet

# Fonction pour la capture de paquets en temps réel
def start_capture():
    capture_iface = iface_entry.get()
    sniff(iface=capture_iface, prn=analyze_packet)

# Interface utilisateur
root = Tk()
root.title("Tableau de bord de capture en temps réel")

# Champ pour entrer l'interface de capture
Label(root, text="Interface de capture:").pack()
iface_entry = Entry(root)
iface_entry.pack()

# Bouton pour démarrer la capture en temps réel
start_button = Button(root, text="Démarrer la capture", command=start_capture)
start_button.pack()

# Texte pour afficher les informations en temps réel
text = Text(root)
text.pack()

root.mainloop()
