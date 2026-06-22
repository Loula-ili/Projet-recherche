"""
Module de hachage cryptographique pour l'intégrité des données industrielles
Projet NARRATE - Garantir l'intégrité des données dans les processus industriels
"""

import hashlib
import json
from typing import Any, Dict, Union
from datetime import datetime


class DataHasher:
    """
    Classe pour gérer le hachage cryptographique des données industrielles.
    Supporte SHA-256, SHA-3 et d'autres algorithmes.
    """
    
    SUPPORTED_ALGORITHMS = ['sha256', 'sha3_256', 'sha3_512', 'blake2b']
    
    def __init__(self, algorithm: str = 'sha256'):
        """
        Initialise le hasher avec l'algorithme spécifié.
        
        Args:
            algorithm: Algorithme de hachage ('sha256', 'sha3_256', 'sha3_512', 'blake2b')
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Algorithme non supporté. Utilisez: {self.SUPPORTED_ALGORITHMS}")
        self.algorithm = algorithm
    
    def hash_data(self, data: Union[str, bytes, Dict, list]) -> str:
        """
        Hash des données avec l'algorithme configuré.
        
        Args:
            data: Données à hasher (string, bytes, dict ou list)
            
        Returns:
            Hash hexadécimal des données
        """
        # Conversion des données en bytes
        if isinstance(data, dict) or isinstance(data, list):
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = str(data).encode('utf-8')
        
        # Calcul du hash
        if self.algorithm == 'sha256':
            return hashlib.sha256(data_bytes).hexdigest()
        elif self.algorithm == 'sha3_256':
            return hashlib.sha3_256(data_bytes).hexdigest()
        elif self.algorithm == 'sha3_512':
            return hashlib.sha3_512(data_bytes).hexdigest()
        elif self.algorithm == 'blake2b':
            return hashlib.blake2b(data_bytes).hexdigest()
    
    def verify_integrity(self, data: Union[str, bytes, Dict, list], expected_hash: str) -> bool:
        """
        Vérifie l'intégrité des données en comparant avec le hash attendu.
        
        Args:
            data: Données à vérifier
            expected_hash: Hash attendu
            
        Returns:
            True si l'intégrité est vérifiée, False sinon
        """
        computed_hash = self.hash_data(data)
        return computed_hash == expected_hash
    
    def create_integrity_record(self, data: Any, metadata: Dict = None) -> Dict:
        """
        Crée un enregistrement d'intégrité complet avec timestamp et métadonnées.
        
        Args:
            data: Données à enregistrer
            metadata: Métadonnées supplémentaires (optionnel)
            
        Returns:
            Dictionnaire contenant les données, le hash, timestamp et métadonnées
        """
        record = {
            'data': data,
            'hash': self.hash_data(data),
            'algorithm': self.algorithm,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        return record
    
    def verify_record(self, record: Dict) -> bool:
        """
        Vérifie l'intégrité d'un enregistrement complet.
        
        Args:
            record: Enregistrement d'intégrité
            
        Returns:
            True si l'enregistrement est valide, False sinon
        """
        if 'data' not in record or 'hash' not in record:
            return False
        
        # Réinitialiser l'algorithme si nécessaire
        original_algo = self.algorithm
        if 'algorithm' in record:
            self.algorithm = record['algorithm']
        
        is_valid = self.verify_integrity(record['data'], record['hash'])
        
        # Restaurer l'algorithme original
        self.algorithm = original_algo
        
        return is_valid


class IndustrialDataChain:
    """
    Chaîne d'intégrité pour tracer les données industrielles avec hachage séquentiel.
    Similaire à une blockchain simplifiée.
    """
    
    def __init__(self, algorithm: str = 'sha256'):
        """
        Initialise la chaîne d'intégrité.
        
        Args:
            algorithm: Algorithme de hachage à utiliser
        """
        self.hasher = DataHasher(algorithm)
        self.chain = []
        self.previous_hash = "0" * 64  # Hash initial (genesis)
    
    def add_block(self, data: Any, metadata: Dict = None) -> Dict:
        """
        Ajoute un nouveau bloc à la chaîne avec référence au bloc précédent.
        
        Args:
            data: Données du bloc
            metadata: Métadonnées supplémentaires
            
        Returns:
            Le bloc ajouté
        """
        block = {
            'index': len(self.chain),
            'timestamp': datetime.utcnow().isoformat(),
            'data': data,
            'previous_hash': self.previous_hash,
            'metadata': metadata or {}
        }
        
        # Hash du bloc complet incluant previous_hash
        block_content = {
            'index': block['index'],
            'timestamp': block['timestamp'],
            'data': block['data'],
            'previous_hash': block['previous_hash'],
            'metadata': block['metadata']
        }
        block['hash'] = self.hasher.hash_data(block_content)
        
        self.chain.append(block)
        self.previous_hash = block['hash']
        
        return block
    
    def verify_chain(self) -> Dict:
        """
        Vérifie l'intégrité de toute la chaîne.
        
        Returns:
            Dictionnaire avec le statut de validation et les détails
        """
        if len(self.chain) == 0:
            return {'valid': True, 'errors': []}
        
        errors = []
        
        for i, block in enumerate(self.chain):
            # Vérifier le hash du bloc
            block_content = {
                'index': block['index'],
                'timestamp': block['timestamp'],
                'data': block['data'],
                'previous_hash': block['previous_hash'],
                'metadata': block['metadata']
            }
            expected_hash = self.hasher.hash_data(block_content)
            
            if block['hash'] != expected_hash:
                errors.append(f"Bloc {i}: Hash invalide")
            
            # Vérifier le lien avec le bloc précédent
            if i > 0:
                if block['previous_hash'] != self.chain[i-1]['hash']:
                    errors.append(f"Bloc {i}: Lien avec bloc précédent rompu")
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'blocks_checked': len(self.chain)
        }
    
    def get_block(self, index: int) -> Dict:
        """Récupère un bloc par son index."""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def get_chain_length(self) -> int:
        """Retourne la longueur de la chaîne."""
        return len(self.chain)


if __name__ == "__main__":
    # Tests de démonstration
    print("=== Test du module de hachage ===\n")
    
    # Test 1: Hachage simple
    hasher = DataHasher('sha256')
    data = {"temperature": 85.5, "pressure": 1013.25, "sensor_id": "SENSOR_001"}
    hash_value = hasher.hash_data(data)
    print(f"1. Données capteur: {data}")
    print(f"   Hash SHA-256: {hash_value}\n")
    
    # Test 2: Vérification d'intégrité
    is_valid = hasher.verify_integrity(data, hash_value)
    print(f"2. Vérification d'intégrité: {'✓ VALIDE' if is_valid else '✗ INVALIDE'}\n")
    
    # Test 3: Détection de falsification
    tampered_data = {"temperature": 90.0, "pressure": 1013.25, "sensor_id": "SENSOR_001"}
    is_valid_tampered = hasher.verify_integrity(tampered_data, hash_value)
    print(f"3. Données modifiées: {tampered_data}")
    print(f"   Vérification: {'✓ VALIDE' if is_valid_tampered else '✗ INVALIDE (falsification détectée)'}\n")
    
    # Test 4: Chaîne d'intégrité
    print("=== Test de la chaîne d'intégrité ===\n")
    chain = IndustrialDataChain('sha256')
    
    # Ajout de plusieurs mesures
    chain.add_block({"temp": 85.5, "sensor": "S1"}, {"location": "Zone A"})
    chain.add_block({"temp": 86.2, "sensor": "S1"}, {"location": "Zone A"})
    chain.add_block({"temp": 85.8, "sensor": "S1"}, {"location": "Zone A"})
    
    print(f"4. Chaîne créée avec {chain.get_chain_length()} blocs")
    
    # Vérification de la chaîne
    validation = chain.verify_chain()
    print(f"   Validation: {'✓ CHAÎNE INTÈGRE' if validation['valid'] else '✗ CHAÎNE COMPROMISE'}")
    print(f"   Blocs vérifiés: {validation['blocks_checked']}\n")
    
    # Test 5: Simulation d'attaque
    print("5. Simulation d'attaque - Modification d'un bloc...")
    if len(chain.chain) > 1:
        chain.chain[1]['data']['temp'] = 999.9  # Falsification
        validation_after_attack = chain.verify_chain()
        print(f"   Validation après attaque: {'✓ CHAÎNE INTÈGRE' if validation_after_attack['valid'] else '✗ CHAÎNE COMPROMISE'}")
        if validation_after_attack['errors']:
            print(f"   Erreurs détectées: {validation_after_attack['errors']}")
