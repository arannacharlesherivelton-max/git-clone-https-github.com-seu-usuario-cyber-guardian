import socket
import time
import requests
import threading
from collections import defaultdict

class ThreatIntelligence:
    def __init__(self):
        # Armazena o histórico recente de conexões (IP -> lista de timestamps)
        self.ip_tracker = defaultdict(list)
        self.threshold = 50 # Dispara se houver mais de 50 conexões em 10 segundos
        
        # Endereços dos nossos microsserviços
        self.java_logger_url = "http://localhost:8080/api/logs/alert"
        self.node_dashboard_url = "http://localhost:3000/webhook/threat"
        self.ruby_agent_url = "http://localhost:4567/block_ip"
        
        # Lista de IPs já bloqueados para evitar requisições duplicadas
        self.blocked_ips = set()

    def analyze_traffic(self, source_ip):
        if source_ip in self.blocked_ips:
            return # Ignora IPs que já foram neutralizados

        current_time = time.time()
        
        # 1. Limpa registros mais velhos que 10 segundos (Janela de Tempo)
        self.ip_tracker[source_ip] = [t for t in self.ip_tracker[source_ip] if current_time - t < 10]
        
        # 2. Adiciona a nova conexão
        self.ip_tracker[source_ip].append(current_time)
        
        # 3. CAMADA HEURÍSTICA: Verifica taxa de conexão (Possível DDoS ou Port Scan)
        if len(self.ip_tracker[source_ip]) > self.threshold:
            self.trigger_alert(source_ip, "Heurística: Possível DDoS / Port Scan")
            return

        # 4. CAMADA DE IA (Espaço para o Modelo)
        # Aqui você futuramente passaria metadados (tamanho do pacote, portas, etc)
        # para um modelo Scikit-Learn ou TensorFlow:
        # 
        # features = extract_features(pacote)
        # is_anomaly = ai_model.predict([features])
        # if is_anomaly:
        #     self.trigger_alert(source_ip, "IA: Comportamento Anômalo Detectado")

    def trigger_alert(self, ip, threat_type):
        print(f"\n[Python Core] 🚨 AMEAÇA DETECTADA: {ip} - {threat_type}")
        self.blocked_ips.add(ip)
        
        payload = {"ip": ip, "type": threat_type}
        
        # Dispara notificações em threads separadas para não travar a análise de novos pacotes
        threading.Thread(target=self._notify_services, args=(payload,)).start()

    def _notify_services(self, payload):
        ip = payload["ip"]
        
        # 1. Avisa o Node.js (Pisca no Dashboard)
        try:
            requests.post(self.node_dashboard_url, json=payload, timeout=2)
            print("  ✅ Node.js: Dashboard atualizado.")
        except:
            print("  ❌ Node.js: Falha ao contatar Dashboard.")

        # 2. Avisa o Java (Salva no banco de logs)
        try:
            requests.post(self.java_logger_url, json=payload, timeout=2)
            print("  ✅ Java: Log registrado com sucesso.")
        except:
            print("  ❌ Java: Falha ao contatar serviço de Logs.")

        # 3. Aciona o Ruby (Executa o bloqueio no Firewall)
        try:
            requests.post(self.ruby_agent_url, json={"ip": ip}, timeout=3)
            print("  ✅ Ruby: IP isolado no firewall local.")
        except:
            print("  ❌ Ruby: Falha ao acionar contenção.")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Endereço onde o Python escuta os sensores (C/C++)
    server.bind(('localhost', 9090)) 
    server.listen(5)
    
    ai_core = ThreatIntelligence()
    print("CyberGuardian Core iniciado. Aguardando telemetria...")
    
    while True:
        client, addr = server.accept()
        # Recebe o IP enviado pelo sensor C++
        data = client.recv(1024).decode('utf-8').strip()
        if data:
            ai_core.analyze_traffic(data)
        client.close()

if __name__ == "__main__":
    start_server()
