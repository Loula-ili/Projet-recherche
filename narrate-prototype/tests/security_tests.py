"""
Tests de robustesse et scénarios d'attaque sur le cadre d'intégrité NARRATE
Évaluation des performances et résistance aux falsifications
"""

import sys
import os
import time
import json
from typing import List, Dict, Tuple

# Ajout du chemin src au PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'simulations'))

from hashing import DataHasher, IndustrialDataChain
from signature import RSASignature, ECDSASignature, SignedDataPackage
from industrial_simulator import IndustrialSimulation


class SecurityTestSuite:
    """
    Suite de tests de sécurité pour le cadre NARRATE.
    """
    
    def __init__(self):
        self.results = {
            'tests_executed': 0,
            'tests_passed': 0,
            'tests_failed': 0,
            'attack_scenarios': []
        }
    
    def test_hash_collision_resistance(self, iterations: int = 1000) -> Dict:
        """
        Test de résistance aux collisions de hash.
        
        Args:
            iterations: Nombre d'itérations de test
            
        Returns:
            Résultats du test
        """
        print(f"\n🔍 Test 1: Résistance aux collisions de hash ({iterations} itérations)")
        
        hasher = DataHasher('sha256')
        hashes = set()
        collision_found = False
        
        start_time = time.time()
        
        for i in range(iterations):
            data = {"iteration": i, "timestamp": time.time(), "value": i * 1.5}
            hash_value = hasher.hash_data(data)
            
            if hash_value in hashes:
                collision_found = True
                break
            hashes.add(hash_value)
        
        duration = time.time() - start_time
        
        result = {
            'test_name': 'Hash Collision Resistance',
            'passed': not collision_found,
            'hashes_generated': len(hashes),
            'collisions_found': 1 if collision_found else 0,
            'duration_seconds': round(duration, 3),
            'hash_rate': round(len(hashes) / duration, 2) if duration > 0 else float('inf')
        }
        
        self.results['tests_executed'] += 1
        if result['passed']:
            self.results['tests_passed'] += 1
            print(f"   ✓ PASSÉ - {len(hashes)} hashs uniques générés")
        else:
            self.results['tests_failed'] += 1
            print(f"   ✗ ÉCHOUÉ - Collision détectée")
        
        print(f"   Performance: {result['hash_rate']} hash/s")
        
        return result
    
    def test_data_tampering_detection(self) -> Dict:
        """
        Test de détection de falsification de données.
        
        Returns:
            Résultats du test
        """
        print(f"\n🔍 Test 2: Détection de falsification de données")
        
        hasher = DataHasher('sha256')
        
        # Données originales
        original_data = {
            "sensor": "TEMP_001",
            "value": 85.5,
            "unit": "°C",
            "location": "Zone A"
        }
        
        original_hash = hasher.hash_data(original_data)
        
        # Scénarios d'attaque
        attack_scenarios = [
            {"sensor": "TEMP_001", "value": 90.0, "unit": "°C", "location": "Zone A"},  # Valeur modifiée
            {"sensor": "TEMP_002", "value": 85.5, "unit": "°C", "location": "Zone A"},  # ID modifié
            {"sensor": "TEMP_001", "value": 85.5, "unit": "°C", "location": "Zone B"},  # Localisation modifiée
            {"sensor": "TEMP_001", "value": 85.5001, "unit": "°C", "location": "Zone A"},  # Modification minime
        ]
        
        detected = 0
        
        for i, tampered in enumerate(attack_scenarios):
            is_valid = hasher.verify_integrity(tampered, original_hash)
            if not is_valid:
                detected += 1
        
        result = {
            'test_name': 'Data Tampering Detection',
            'passed': detected == len(attack_scenarios),
            'attack_scenarios': len(attack_scenarios),
            'detected': detected,
            'detection_rate': round((detected / len(attack_scenarios)) * 100, 1)
        }
        
        self.results['tests_executed'] += 1
        if result['passed']:
            self.results['tests_passed'] += 1
            print(f"   ✓ PASSÉ - {detected}/{len(attack_scenarios)} falsifications détectées")
        else:
            self.results['tests_failed'] += 1
            print(f"   ✗ ÉCHOUÉ - {len(attack_scenarios) - detected} falsifications non détectées")
        
        return result
    
    def test_chain_integrity_attack(self) -> Dict:
        """
        Test d'attaque sur la chaîne d'intégrité.
        
        Returns:
            Résultats du test
        """
        print(f"\n🔍 Test 3: Attaque de la chaîne d'intégrité")
        
        chain = IndustrialDataChain('sha256')
        
        # Création d'une chaîne valide
        for i in range(5):
            chain.add_block(
                data={"sensor": "S1", "value": 80 + i, "iteration": i},
                metadata={"timestamp": time.time()}
            )
        
        # Vérification initiale
        validation_before = chain.verify_chain()
        
        # Scénarios d'attaque
        attack_results = []
        
        # Attaque 1: Modification d'un bloc au milieu
        original_value = chain.chain[2]['data']['value']
        chain.chain[2]['data']['value'] = 999
        validation_attack1 = chain.verify_chain()
        attack_results.append({
            'attack': 'Modification bloc milieu',
            'detected': not validation_attack1['valid']
        })
        chain.chain[2]['data']['value'] = original_value  # Restauration
        
        # Attaque 2: Modification du hash d'un bloc
        original_hash = chain.chain[1]['hash']
        chain.chain[1]['hash'] = "0" * 64
        validation_attack2 = chain.verify_chain()
        attack_results.append({
            'attack': 'Modification hash',
            'detected': not validation_attack2['valid']
        })
        chain.chain[1]['hash'] = original_hash  # Restauration
        
        # Attaque 3: Rupture du lien previous_hash
        original_prev = chain.chain[3]['previous_hash']
        chain.chain[3]['previous_hash'] = "fake_hash"
        validation_attack3 = chain.verify_chain()
        attack_results.append({
            'attack': 'Rupture lien chaîne',
            'detected': not validation_attack3['valid']
        })
        
        detected_attacks = sum(1 for r in attack_results if r['detected'])
        
        result = {
            'test_name': 'Chain Integrity Attack',
            'passed': detected_attacks == len(attack_results),
            'attacks_tested': len(attack_results),
            'attacks_detected': detected_attacks,
            'chain_valid_before': validation_before['valid'],
            'attack_details': attack_results
        }
        
        self.results['tests_executed'] += 1
        if result['passed']:
            self.results['tests_passed'] += 1
            print(f"   ✓ PASSÉ - Toutes les attaques détectées ({detected_attacks}/{len(attack_results)})")
        else:
            self.results['tests_failed'] += 1
            print(f"   ✗ ÉCHOUÉ - {len(attack_results) - detected_attacks} attaques non détectées")
        
        return result
    
    def test_signature_forgery_resistance(self) -> Dict:
        """
        Test de résistance à la falsification de signature.
        
        Returns:
            Résultats du test
        """
        print(f"\n🔍 Test 4: Résistance à la falsification de signature")
        
        # Test avec ECDSA
        signer = ECDSASignature('SECP256R1')
        private_key, public_key = signer.generate_keys()
        
        data = {"machine": "M1", "status": "running", "value": 100}
        valid_signature = signer.sign(data)
        
        # Tentatives de falsification
        forgery_attempts = [
            valid_signature[:-5] + "XXXXX",  # Modification de la fin
            valid_signature[:10] + "X" * 10 + valid_signature[20:],  # Modification au milieu
            "fake_signature_" + valid_signature[:20],  # Ajout de préfixe
            valid_signature + "extra",  # Ajout de suffixe
        ]
        
        forgeries_detected = 0
        
        for fake_sig in forgery_attempts:
            try:
                is_valid = signer.verify(data, fake_sig)
                if not is_valid:
                    forgeries_detected += 1
            except:
                forgeries_detected += 1  # Exception = falsification détectée
        
        result = {
            'test_name': 'Signature Forgery Resistance',
            'passed': forgeries_detected == len(forgery_attempts),
            'forgery_attempts': len(forgery_attempts),
            'detected': forgeries_detected,
            'algorithm': 'ECDSA-SECP256R1'
        }
        
        self.results['tests_executed'] += 1
        if result['passed']:
            self.results['tests_passed'] += 1
            print(f"   ✓ PASSÉ - Toutes les falsifications détectées ({forgeries_detected}/{len(forgery_attempts)})")
        else:
            self.results['tests_failed'] += 1
            print(f"   ✗ ÉCHOUÉ - {len(forgery_attempts) - forgeries_detected} falsifications acceptées")
        
        return result
    
    def test_performance_comparison(self, iterations: int = 100) -> Dict:
        """
        Comparaison des performances entre algorithmes.
        
        Args:
            iterations: Nombre d'itérations pour le benchmark
            
        Returns:
            Résultats de performance
        """
        print(f"\n🔍 Test 5: Comparaison de performances ({iterations} itérations)")
        
        data = {"sensor": "TEMP_001", "value": 85.5, "timestamp": time.time()}
        
        # Test des algorithmes de hachage
        hash_algos = ['sha256', 'sha3_256', 'blake2b']
        hash_results = {}
        
        for algo in hash_algos:
            hasher = DataHasher(algo)
            start = time.time()
            for _ in range(iterations):
                hasher.hash_data(data)
            duration = time.time() - start
            hash_results[algo] = {
                'duration': round(duration, 4),
                'ops_per_sec': round(iterations / duration, 2) if duration > 0 else float('inf')
            }
        
        print(f"\n   Hachage (ops/sec):")
        for algo, res in hash_results.items():
            print(f"      {algo}: {res['ops_per_sec']}")
        
        # Test des algorithmes de signature
        print(f"\n   Signature numérique:")
        
        # RSA
        rsa_signer = RSASignature(2048)
        rsa_signer.generate_keys()
        
        start = time.time()
        for _ in range(iterations):
            rsa_signer.sign(data)
        rsa_sign_time = time.time() - start
        
        signature = rsa_signer.sign(data)
        start = time.time()
        for _ in range(iterations):
            rsa_signer.verify(data, signature)
        rsa_verify_time = time.time() - start
        
        print(f"      RSA-2048:")
        print(f"         Signature: {round(iterations/rsa_sign_time, 2) if rsa_sign_time > 0 else float('inf')} ops/sec")
        print(f"         Vérification: {round(iterations/rsa_verify_time, 2) if rsa_verify_time > 0 else float('inf')} ops/sec")
        
        # ECDSA
        ecdsa_signer = ECDSASignature('SECP256R1')
        ecdsa_signer.generate_keys()
        
        start = time.time()
        for _ in range(iterations):
            ecdsa_signer.sign(data)
        ecdsa_sign_time = time.time() - start
        
        signature = ecdsa_signer.sign(data)
        start = time.time()
        for _ in range(iterations):
            ecdsa_signer.verify(data, signature)
        ecdsa_verify_time = time.time() - start
        
        print(f"      ECDSA-SECP256R1:")
        print(f"         Signature: {round(iterations/ecdsa_sign_time, 2) if ecdsa_sign_time > 0 else float('inf')} ops/sec")
        print(f"         Vérification: {round(iterations/ecdsa_verify_time, 2) if ecdsa_verify_time > 0 else float('inf')} ops/sec")
        
        result = {
            'test_name': 'Performance Comparison',
            'passed': True,
            'iterations': iterations,
            'hashing': hash_results,
            'signature': {
                'RSA': {
                    'sign_ops_per_sec': round(iterations/rsa_sign_time, 2) if rsa_sign_time > 0 else float('inf'),
                    'verify_ops_per_sec': round(iterations/rsa_verify_time, 2) if rsa_verify_time > 0 else float('inf')
                },
                'ECDSA': {
                    'sign_ops_per_sec': round(iterations/ecdsa_sign_time, 2) if ecdsa_sign_time > 0 else float('inf'),
                    'verify_ops_per_sec': round(iterations/ecdsa_verify_time, 2) if ecdsa_verify_time > 0 else float('inf')
                }
            }
        }
        
        self.results['tests_executed'] += 1
        self.results['tests_passed'] += 1
        print(f"\n   ✓ Benchmark complété")
        
        return result
    
    def run_all_tests(self) -> Dict:
        """
        Exécute tous les tests de sécurité.
        
        Returns:
            Résultats complets de tous les tests
        """
        print("=" * 70)
        print("SUITE DE TESTS DE ROBUSTESSE - Projet NARRATE")
        print("=" * 70)
        
        test_results = []
        
        # Exécution des tests
        test_results.append(self.test_hash_collision_resistance(1000))
        test_results.append(self.test_data_tampering_detection())
        test_results.append(self.test_chain_integrity_attack())
        test_results.append(self.test_signature_forgery_resistance())
        test_results.append(self.test_performance_comparison(100))
        
        # Résumé final
        print("\n" + "=" * 70)
        print("RÉSUMÉ DES TESTS")
        print("=" * 70)
        print(f"Tests exécutés: {self.results['tests_executed']}")
        print(f"Tests réussis: {self.results['tests_passed']} ✓")
        print(f"Tests échoués: {self.results['tests_failed']} ✗")
        success_rate = (self.results['tests_passed'] / self.results['tests_executed']) * 100
        print(f"Taux de réussite: {success_rate:.1f}%")
        print("=" * 70)
        
        self.results['detailed_results'] = test_results
        
        return self.results


if __name__ == "__main__":
    # Exécution de la suite de tests
    test_suite = SecurityTestSuite()
    results = test_suite.run_all_tests()
    
    # Sauvegarde des résultats
    output_file = os.path.join(os.path.dirname(__file__), '..', 'docs', 'test_results.json')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 Résultats sauvegardés dans: test_results.json")
