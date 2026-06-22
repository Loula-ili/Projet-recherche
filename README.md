# NARRATE — Prototype d'intégrité des données industrielles

Prototype de recherche pour garantir l'intégrité et l'authenticité des données dans les environnements industriels, à l'aide de hachage cryptographique, de signatures numériques et d'une chaîne de blocs légère.

## Structure du projet

```
narrate-prototype/
├── src/
│   ├── hashing.py          # Hachage cryptographique (SHA-256, SHA-3, BLAKE2b)
│   └── signature.py        # Signatures numériques (RSA, ECDSA)
├── simulations/
│   └── industrial_simulator.py  # Simulateur de capteurs et machines industriels
├── tests/
│   └── security_tests.py   # Suite de tests de robustesse et scénarios d'attaque
└── docs/
    └── test_results.json   # Résultats des derniers tests
```

## Fonctionnalités

### Hachage (`src/hashing.py`)
- Classe `DataHasher` : hachage de données arbitraires (dict, str, bytes) avec SHA-256, SHA-3-256, SHA-3-512 ou BLAKE2b
- Vérification d'intégrité via comparaison de hash
- `IndustrialDataChain` : chaîne d'enregistrements liés par leurs hashs, résistante à la falsification

### Signatures numériques (`src/signature.py`)
- `RSASignature` : génération de paires de clés RSA (2048/3072/4096 bits), signature et vérification
- `ECDSASignature` : signature sur courbe elliptique (plus légère)
- `SignedDataPackage` : paquet de données signé avec métadonnées et horodatage

### Simulateur industriel (`simulations/industrial_simulator.py`)
- `IndustrialSensor` : génération de données capteurs (température, pression, vibration…) avec variation naturelle
- `MachineStatus` : état de machines industrielles
- `IndustrialSimulation` : orchestration d'une simulation complète avec plusieurs capteurs et machines

## Installation

```bash
pip install cryptography
```

## Utilisation

```python
from src.hashing import DataHasher, IndustrialDataChain
from src.signature import RSASignature

# Hachage d'une mesure capteur
hasher = DataHasher('sha256')
record = hasher.create_integrity_record({"sensor": "T01", "value": 73.4})

# Vérification d'intégrité
is_valid = hasher.verify_integrity(record['data'], record['hash'])

# Signature RSA
rsa = RSASignature(key_size=2048)
private_pem, public_pem = rsa.generate_keys()
signature = rsa.sign({"sensor": "T01", "value": 73.4})
```

## Tests de sécurité

```bash
python tests/security_tests.py
```

Les tests couvrent :
- Résistance aux collisions de hash
- Détection de falsification de données
- Résistance aux attaques sur la chaîne d'intégrité
- Performance des signatures RSA/ECDSA

**Derniers résultats** : 5/5 tests passés — taux de détection des attaques : 100 %
