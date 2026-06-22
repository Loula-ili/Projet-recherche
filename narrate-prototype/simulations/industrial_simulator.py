"""
Simulateur de flux de données industriels avec capteurs, machines et jumeaux numériques
Projet NARRATE - Environnement expérimental pour tests d'intégrité
"""

import random
import time
import json
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
import threading


@dataclass
class SensorData:
    """Données d'un capteur industriel."""
    sensor_id: str
    sensor_type: str
    value: float
    unit: str
    timestamp: str
    location: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MachineStatus:
    """État d'une machine industrielle."""
    machine_id: str
    status: str  # 'running', 'idle', 'maintenance', 'error'
    production_rate: float
    temperature: float
    vibration_level: float
    timestamp: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class IndustrialSensor:
    """
    Simulateur de capteur industriel générant des données périodiques.
    """
    
    def __init__(self, sensor_id: str, sensor_type: str, location: str,
                 value_range: tuple = (0, 100), unit: str = "unit"):
        """
        Initialise un capteur industriel.
        
        Args:
            sensor_id: Identifiant unique du capteur
            sensor_type: Type de capteur (temperature, pressure, vibration, etc.)
            location: Localisation dans l'usine
            value_range: Plage de valeurs (min, max)
            unit: Unité de mesure
        """
        self.sensor_id = sensor_id
        self.sensor_type = sensor_type
        self.location = location
        self.value_range = value_range
        self.unit = unit
        self.current_value = random.uniform(*value_range)
    
    def read(self) -> SensorData:
        """
        Lit une valeur du capteur avec variation naturelle.
        
        Returns:
            Objet SensorData avec la mesure
        """
        # Variation naturelle: +/- 5% de la valeur actuelle
        variation = self.current_value * random.uniform(-0.05, 0.05)
        self.current_value += variation
        
        # Garder dans les limites
        self.current_value = max(self.value_range[0], 
                                min(self.value_range[1], self.current_value))
        
        return SensorData(
            sensor_id=self.sensor_id,
            sensor_type=self.sensor_type,
            value=round(self.current_value, 2),
            unit=self.unit,
            timestamp=datetime.utcnow().isoformat(),
            location=self.location
        )
    
    def inject_anomaly(self, anomaly_value: float):
        """Injecte une valeur anormale pour tests."""
        self.current_value = anomaly_value


class IndustrialMachine:
    """
    Simulateur de machine industrielle avec capteurs intégrés.
    """
    
    STATUSES = ['running', 'idle', 'maintenance', 'error']
    
    def __init__(self, machine_id: str, production_capacity: float = 100.0):
        """
        Initialise une machine industrielle.
        
        Args:
            machine_id: Identifiant de la machine
            production_capacity: Capacité de production maximale (unités/heure)
        """
        self.machine_id = machine_id
        self.production_capacity = production_capacity
        self.status = 'running'
        self.temperature = random.uniform(60, 80)
        self.vibration = random.uniform(0.1, 0.5)
    
    def get_status(self) -> MachineStatus:
        """
        Obtient l'état actuel de la machine.
        
        Returns:
            Objet MachineStatus avec l'état complet
        """
        # Mise à jour des paramètres selon le statut
        if self.status == 'running':
            production_rate = self.production_capacity * random.uniform(0.8, 1.0)
            self.temperature += random.uniform(-2, 3)
            self.vibration += random.uniform(-0.1, 0.1)
        elif self.status == 'idle':
            production_rate = 0
            self.temperature -= 1
            self.vibration = random.uniform(0.05, 0.15)
        elif self.status == 'error':
            production_rate = 0
            self.temperature += random.uniform(5, 10)
            self.vibration += random.uniform(0.5, 1.0)
        else:  # maintenance
            production_rate = 0
            self.temperature = random.uniform(20, 30)
            self.vibration = 0
        
        # Normalisation des valeurs
        self.temperature = max(20, min(120, self.temperature))
        self.vibration = max(0, min(2.0, self.vibration))
        
        return MachineStatus(
            machine_id=self.machine_id,
            status=self.status,
            production_rate=round(production_rate, 2),
            temperature=round(self.temperature, 2),
            vibration_level=round(self.vibration, 2),
            timestamp=datetime.utcnow().isoformat()
        )
    
    def change_status(self, new_status: str):
        """Change le statut de la machine."""
        if new_status in self.STATUSES:
            self.status = new_status


class DigitalTwin:
    """
    Jumeau numérique collectant et analysant les données de capteurs et machines.
    """
    
    def __init__(self, twin_id: str):
        """
        Initialise un jumeau numérique.
        
        Args:
            twin_id: Identifiant du jumeau numérique
        """
        self.twin_id = twin_id
        self.sensors: List[IndustrialSensor] = []
        self.machines: List[IndustrialMachine] = []
        self.data_buffer: List[Dict] = []
        self.max_buffer_size = 100
    
    def register_sensor(self, sensor: IndustrialSensor):
        """Enregistre un capteur dans le jumeau numérique."""
        self.sensors.append(sensor)
    
    def register_machine(self, machine: IndustrialMachine):
        """Enregistre une machine dans le jumeau numérique."""
        self.machines.append(machine)
    
    def collect_data(self) -> Dict:
        """
        Collecte toutes les données des capteurs et machines.
        
        Returns:
            Dictionnaire avec toutes les données collectées
        """
        collection = {
            'twin_id': self.twin_id,
            'timestamp': datetime.utcnow().isoformat(),
            'sensors': [sensor.read().to_dict() for sensor in self.sensors],
            'machines': [machine.get_status().to_dict() for machine in self.machines]
        }
        
        # Ajout au buffer
        self.data_buffer.append(collection)
        if len(self.data_buffer) > self.max_buffer_size:
            self.data_buffer.pop(0)
        
        return collection
    
    def analyze_data(self) -> Dict:
        """
        Analyse les données collectées pour détecter des anomalies.
        
        Returns:
            Rapport d'analyse avec alertes
        """
        if not self.data_buffer:
            return {'status': 'no_data', 'alerts': []}
        
        latest = self.data_buffer[-1]
        alerts = []
        
        # Analyse des machines
        for machine_data in latest.get('machines', []):
            if machine_data['status'] == 'error':
                alerts.append({
                    'level': 'critical',
                    'source': machine_data['machine_id'],
                    'message': 'Machine en erreur'
                })
            
            if machine_data['temperature'] > 100:
                alerts.append({
                    'level': 'warning',
                    'source': machine_data['machine_id'],
                    'message': f"Température élevée: {machine_data['temperature']}°C"
                })
            
            if machine_data['vibration_level'] > 1.5:
                alerts.append({
                    'level': 'warning',
                    'source': machine_data['machine_id'],
                    'message': f"Vibrations anormales: {machine_data['vibration_level']}"
                })
        
        # Analyse des capteurs (valeurs extrêmes)
        for sensor_data in latest.get('sensors', []):
            if sensor_data['sensor_type'] == 'temperature' and sensor_data['value'] > 90:
                alerts.append({
                    'level': 'warning',
                    'source': sensor_data['sensor_id'],
                    'message': f"Température capteur élevée: {sensor_data['value']}{sensor_data['unit']}"
                })
        
        return {
            'status': 'analyzed',
            'timestamp': datetime.utcnow().isoformat(),
            'data_points': len(self.data_buffer),
            'alerts': alerts
        }
    
    def get_statistics(self) -> Dict:
        """
        Calcule des statistiques sur les données collectées.
        
        Returns:
            Statistiques agrégées
        """
        if not self.data_buffer:
            return {}
        
        stats = {
            'twin_id': self.twin_id,
            'total_collections': len(self.data_buffer),
            'sensors_count': len(self.sensors),
            'machines_count': len(self.machines),
            'time_span': {
                'first': self.data_buffer[0]['timestamp'] if self.data_buffer else None,
                'last': self.data_buffer[-1]['timestamp'] if self.data_buffer else None
            }
        }
        
        return stats


class IndustrialSimulation:
    """
    Simulation complète d'un environnement industriel avec flux de données.
    """
    
    def __init__(self, name: str = "Simulation NARRATE"):
        """
        Initialise la simulation industrielle.
        
        Args:
            name: Nom de la simulation
        """
        self.name = name
        self.digital_twin = DigitalTwin("DT_MAIN")
        self.running = False
    
    def setup_environment(self):
        """Configure l'environnement avec capteurs et machines."""
        # Création de capteurs
        sensors = [
            IndustrialSensor("TEMP_01", "temperature", "Zone A", (60, 95), "°C"),
            IndustrialSensor("TEMP_02", "temperature", "Zone B", (55, 90), "°C"),
            IndustrialSensor("PRESS_01", "pressure", "Zone A", (980, 1050), "hPa"),
            IndustrialSensor("VIB_01", "vibration", "Machine M1", (0.1, 1.0), "mm/s"),
            IndustrialSensor("HUM_01", "humidity", "Zone A", (30, 70), "%")
        ]
        
        for sensor in sensors:
            self.digital_twin.register_sensor(sensor)
        
        # Création de machines
        machines = [
            IndustrialMachine("MACHINE_M1", 120.0),
            IndustrialMachine("MACHINE_M2", 100.0),
            IndustrialMachine("MACHINE_M3", 150.0)
        ]
        
        for machine in machines:
            self.digital_twin.register_machine(machine)
        
        print(f"✓ Environnement configuré: {len(sensors)} capteurs, {len(machines)} machines")
    
    def run_cycle(self) -> Dict:
        """
        Exécute un cycle de collecte de données.
        
        Returns:
            Données collectées durant le cycle
        """
        data = self.digital_twin.collect_data()
        return data
    
    def run_continuous(self, duration_seconds: int = 60, interval_seconds: float = 1.0):
        """
        Exécute la simulation en continu pendant une durée donnée.
        
        Args:
            duration_seconds: Durée totale de la simulation
            interval_seconds: Intervalle entre les collectes
        """
        print(f"\n▶ Démarrage simulation '{self.name}' - Durée: {duration_seconds}s")
        self.running = True
        
        start_time = time.time()
        cycles = 0
        
        while self.running and (time.time() - start_time) < duration_seconds:
            self.run_cycle()
            cycles += 1
            time.sleep(interval_seconds)
        
        self.running = False
        print(f"⏹ Simulation terminée - {cycles} cycles exécutés")
        
        # Affichage des statistiques
        stats = self.digital_twin.get_statistics()
        print(f"   Statistiques: {stats['total_collections']} collectes")
        
        # Analyse finale
        analysis = self.digital_twin.analyze_data()
        if analysis['alerts']:
            print(f"   ⚠ {len(analysis['alerts'])} alerte(s) détectée(s)")
        else:
            print(f"   ✓ Aucune anomalie détectée")


if __name__ == "__main__":
    print("=== Simulateur de flux industriels - Projet NARRATE ===\n")
    
    # Création et configuration de la simulation
    sim = IndustrialSimulation("Test NARRATE")
    sim.setup_environment()
    
    print("\n--- Test 1: Collecte unique ---")
    data = sim.run_cycle()
    print(f"Collecte effectuée à: {data['timestamp']}")
    print(f"Capteurs: {len(data['sensors'])} lectures")
    print(f"Machines: {len(data['machines'])} statuts")
    
    print("\n--- Test 2: Analyse des données ---")
    analysis = sim.digital_twin.analyze_data()
    print(f"Statut: {analysis['status']}")
    print(f"Alertes: {len(analysis['alerts'])}")
    
    print("\n--- Test 3: Injection d'anomalie ---")
    # Injection d'une température anormale
    sim.digital_twin.sensors[0].inject_anomaly(150.0)
    data_anomaly = sim.run_cycle()
    analysis_anomaly = sim.digital_twin.analyze_data()
    print(f"Température anormale injectée: {data_anomaly['sensors'][0]['value']}°C")
    print(f"Alertes détectées: {len(analysis_anomaly['alerts'])}")
    if analysis_anomaly['alerts']:
        for alert in analysis_anomaly['alerts']:
            print(f"  - [{alert['level']}] {alert['source']}: {alert['message']}")
    
    print("\n--- Test 4: Simulation continue (10 secondes) ---")
    sim.run_continuous(duration_seconds=10, interval_seconds=0.5)
