from scapy.all import sniff
from collections import defaultdict
import time
import logging

# Configuration des paramètres de détection
SEUIL_PAIQUETS_PAR_IP = 100  # Seuil de paquets par IP dans un intervalle
SEUIL_DEBIT_OCTETS = 1_000_000  # Seuil du débit total en octets dans un intervalle
INTERVALLE_ANALYSE = 10  # Intervalle de temps pour l'analyse (en secondes)

# Configuration du journal
logging.basicConfig(
    filename="ddos_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Variables globales
trafic_ip = defaultdict(int)  # Compteur de paquets par IP source
octets_totaux = 0  # Compteur de la taille totale des paquets

def analyser_paquet(paquet):
    """
    Fonction appelée pour chaque paquet capturé.
    Incrémente le compteur pour l'IP source et la taille totale des paquets.
    """
    global octets_totaux

    if paquet.haslayer("IP"):
        ip_src = paquet["IP"].src
        taille_paquet = len(paquet)  # Taille du paquet en octets
        trafic_ip[ip_src] += 1
        octets_totaux += taille_paquet

def verifier_ddos():
    """
    Vérifie les conditions de détection pour identifier une attaque DDoS.
    """
    global octets_totaux

    print("\n[Analyse] Start of analysis...")
    attaque_detectee = False

    # Vérifier le débit global en octets
    if octets_totaux > SEUIL_DEBIT_OCTETS:
        attaque_detectee = True
        message = f"[ALERT] High total throughput detected : {octets_totaux} octect in the {INTERVALLE_ANALYSE} seconds."
        print(message)
        logging.info(message)

    # Vérifier les IP qui dépassent le seuil de paquets
    for ip, compteur in trafic_ip.items():
        if compteur > SEUIL_PAIQUETS_PAR_IP:
            attaque_detectee = True
            message = f"[ALERT] Potential DDoS attack detected : IP {ip}, {compteur} packets."
            print(message)
            logging.info(message)

    if not attaque_detectee:
        print("[OK] No suspicious behavior detected.")

    # Réinitialiser les compteurs pour le prochain intervalle
    trafic_ip.clear()
    octets_totaux = 0

def main():
    """
    Fonction principale : capture le trafic réseau et vérifie régulièrement les attaques DDoS.
    """
    print("Starting the Advanced DDoS Detection System...")
    print(f"Seuils : {SEUIL_PAIQUETS_PAR_IP} packets by IP and {SEUIL_DEBIT_OCTETS} bytes all {INTERVALLE_ANALYSE} seconds.\n")

    # Capture des paquets réseau en arrière-plan
    while True:
        try:
            sniff(prn=analyser_paquet, store=False, timeout=INTERVALLE_ANALYSE)
            verifier_ddos()
        except KeyboardInterrupt:
            print("\nStopping the program. Thank you for using this tool created by Gentleman 💻👍")
            break

if __name__ == "__main__":
    main()