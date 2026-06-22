"""
Module de signature numérique pour garantir l'authenticité et la non-répudiation
Projet NARRATE - RSA et ECDSA pour données industrielles
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
import json
from typing import Tuple, Union, Dict, Any
from datetime import datetime


class RSASignature:
    """
    Implémentation de la signature numérique RSA pour les données industrielles.
    """
    
    def __init__(self, key_size: int = 2048):
        """
        Initialise le système de signature RSA.
        
        Args:
            key_size: Taille de la clé RSA (2048, 3072, ou 4096 bits)
        """
        if key_size not in [2048, 3072, 4096]:
            raise ValueError("La taille de clé doit être 2048, 3072 ou 4096 bits")
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self) -> Tuple[bytes, bytes]:
        """
        Génère une paire de clés RSA (privée et publique).
        
        Returns:
            Tuple contenant (clé privée PEM, clé publique PEM)
        """
        # Génération de la clé privée
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        
        # Extraction de la clé publique
        self.public_key = self.private_key.public_key()
        
        # Sérialisation en format PEM
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def load_private_key(self, private_key_pem: bytes):
        """Charge une clé privée depuis un format PEM."""
        self.private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
    
    def load_public_key(self, public_key_pem: bytes):
        """Charge une clé publique depuis un format PEM."""
        self.public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
    
    def sign(self, data: Union[str, bytes, Dict]) -> str:
        """
        Signe des données avec la clé privée RSA.
        
        Args:
            data: Données à signer
            
        Returns:
            Signature en base64
        """
        if self.private_key is None:
            raise ValueError("Clé privée non chargée. Générez ou chargez une clé d'abord.")
        
        # Conversion en bytes
        if isinstance(data, dict):
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Signature avec PSS padding et SHA-256
        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify(self, data: Union[str, bytes, Dict], signature: str) -> bool:
        """
        Vérifie une signature avec la clé publique RSA.
        
        Args:
            data: Données originales
            signature: Signature en base64
            
        Returns:
            True si la signature est valide, False sinon
        """
        if self.public_key is None:
            raise ValueError("Clé publique non chargée.")
        
        # Conversion en bytes
        if isinstance(data, dict):
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        signature_bytes = base64.b64decode(signature.encode('utf-8'))
        
        try:
            self.public_key.verify(
                signature_bytes,
                data_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


class ECDSASignature:
    """
    Implémentation de la signature numérique ECDSA (Elliptic Curve) pour les données industrielles.
    Plus rapide et avec des clés plus petites que RSA.
    """
    
    def __init__(self, curve_name: str = 'SECP256R1'):
        """
        Initialise le système de signature ECDSA.
        
        Args:
            curve_name: Nom de la courbe elliptique ('SECP256R1', 'SECP384R1', 'SECP521R1')
        """
        curves = {
            'SECP256R1': ec.SECP256R1(),
            'SECP384R1': ec.SECP384R1(),
            'SECP521R1': ec.SECP521R1()
        }
        
        if curve_name not in curves:
            raise ValueError(f"Courbe non supportée. Utilisez: {list(curves.keys())}")
        
        self.curve = curves[curve_name]
        self.curve_name = curve_name
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self) -> Tuple[bytes, bytes]:
        """
        Génère une paire de clés ECDSA.
        
        Returns:
            Tuple contenant (clé privée PEM, clé publique PEM)
        """
        # Génération de la clé privée
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        
        # Extraction de la clé publique
        self.public_key = self.private_key.public_key()
        
        # Sérialisation
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def load_private_key(self, private_key_pem: bytes):
        """Charge une clé privée depuis un format PEM."""
        self.private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
    
    def load_public_key(self, public_key_pem: bytes):
        """Charge une clé publique depuis un format PEM."""
        self.public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
    
    def sign(self, data: Union[str, bytes, Dict]) -> str:
        """
        Signe des données avec la clé privée ECDSA.
        
        Args:
            data: Données à signer
            
        Returns:
            Signature en base64
        """
        if self.private_key is None:
            raise ValueError("Clé privée non chargée.")
        
        # Conversion en bytes
        if isinstance(data, dict):
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        # Signature avec ECDSA
        signature = self.private_key.sign(
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify(self, data: Union[str, bytes, Dict], signature: str) -> bool:
        """
        Vérifie une signature avec la clé publique ECDSA.
        
        Args:
            data: Données originales
            signature: Signature en base64
            
        Returns:
            True si la signature est valide, False sinon
        """
        if self.public_key is None:
            raise ValueError("Clé publique non chargée.")
        
        # Conversion en bytes
        if isinstance(data, dict):
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        elif isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
        
        signature_bytes = base64.b64decode(signature.encode('utf-8'))
        
        try:
            self.public_key.verify(
                signature_bytes,
                data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


class SignedDataPackage:
    """
    Package complet de données signées avec métadonnées pour usage industriel.
    """
    
    def __init__(self, signer_type: str = 'ECDSA'):
        """
        Initialise le package de données signées.
        
        Args:
            signer_type: Type de signature ('RSA' ou 'ECDSA')
        """
        if signer_type == 'RSA':
            self.signer = RSASignature()
        elif signer_type == 'ECDSA':
            self.signer = ECDSASignature()
        else:
            raise ValueError("Type de signature doit être 'RSA' ou 'ECDSA'")
        
        self.signer_type = signer_type
    
    def create_signed_package(self, data: Any, signer_id: str, metadata: Dict = None) -> Dict:
        """
        Crée un package complet de données signées.
        
        Args:
            data: Données à signer
            signer_id: Identifiant du signataire (ex: "SENSOR_001", "MACHINE_A")
            metadata: Métadonnées additionnelles
            
        Returns:
            Package contenant données, signature, timestamp et métadonnées
        """
        package = {
            'data': data,
            'signer_id': signer_id,
            'signer_type': self.signer_type,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
            'signature': self.signer.sign(data)
        }
        
        return package
    
    def verify_package(self, package: Dict) -> Dict:
        """
        Vérifie l'intégrité et l'authenticité d'un package signé.
        
        Args:
            package: Package à vérifier
            
        Returns:
            Dictionnaire avec le résultat de la vérification
        """
        required_fields = ['data', 'signature', 'signer_type']
        
        # Vérification des champs requis
        for field in required_fields:
            if field not in package:
                return {
                    'valid': False,
                    'reason': f"Champ manquant: {field}",
                    'signature_verified': False
                }
        
        # Vérification de la signature
        try:
            signature_valid = self.signer.verify(package['data'], package['signature'])
            
            return {
                'valid': signature_valid,
                'reason': 'Signature valide' if signature_valid else 'Signature invalide',
                'signature_verified': signature_valid,
                'signer_id': package.get('signer_id', 'Unknown'),
                'timestamp': package.get('timestamp', 'Unknown')
            }
        except Exception as e:
            return {
                'valid': False,
                'reason': f"Erreur de vérification: {str(e)}",
                'signature_verified': False
            }


if __name__ == "__main__":
    print("=== Test du module de signature numérique ===\n")
    
    # Test 1: Signature RSA
    print("1. Test RSA (2048 bits)")
    rsa_signer = RSASignature(2048)
    private_key, public_key = rsa_signer.generate_keys()
    
    data = {"sensor": "TEMP_001", "value": 85.5, "unit": "°C"}
    signature_rsa = rsa_signer.sign(data)
    
    print(f"   Données: {data}")
    print(f"   Signature RSA: {signature_rsa[:50]}...")
    
    is_valid_rsa = rsa_signer.verify(data, signature_rsa)
    print(f"   Vérification: {'✓ VALIDE' if is_valid_rsa else '✗ INVALIDE'}\n")
    
    # Test 2: Signature ECDSA
    print("2. Test ECDSA (SECP256R1)")
    ecdsa_signer = ECDSASignature('SECP256R1')
    ecdsa_private, ecdsa_public = ecdsa_signer.generate_keys()
    
    signature_ecdsa = ecdsa_signer.sign(data)
    print(f"   Signature ECDSA: {signature_ecdsa[:50]}...")
    
    is_valid_ecdsa = ecdsa_signer.verify(data, signature_ecdsa)
    print(f"   Vérification: {'✓ VALIDE' if is_valid_ecdsa else '✗ INVALIDE'}\n")
    
    # Test 3: Détection de falsification
    print("3. Test de falsification")
    tampered_data = {"sensor": "TEMP_001", "value": 999.9, "unit": "°C"}
    is_valid_tampered = ecdsa_signer.verify(tampered_data, signature_ecdsa)
    print(f"   Données modifiées: {tampered_data}")
    print(f"   Vérification: {'✓ VALIDE' if is_valid_tampered else '✗ INVALIDE (falsification détectée)'}\n")
    
    # Test 4: Package signé complet
    print("4. Test de package signé complet")
    packager = SignedDataPackage('ECDSA')
    packager.signer.private_key = ecdsa_signer.private_key
    packager.signer.public_key = ecdsa_signer.public_key
    
    package = packager.create_signed_package(
        data={"pressure": 1013.25, "machine": "M1"},
        signer_id="MACHINE_M1",
        metadata={"location": "Zone A", "type": "pressure_sensor"}
    )
    
    print(f"   Package créé pour: {package['signer_id']}")
    print(f"   Timestamp: {package['timestamp']}")
    
    verification = packager.verify_package(package)
    print(f"   Vérification: {'✓ VALIDE' if verification['valid'] else '✗ INVALIDE'}")
    print(f"   Raison: {verification['reason']}\n")
    
    # Test 5: Comparaison taille des signatures
    print("5. Comparaison des tailles de signature")
    print(f"   Taille signature RSA: {len(signature_rsa)} caractères")
    print(f"   Taille signature ECDSA: {len(signature_ecdsa)} caractères")
    print(f"   Réduction: {100 - (len(signature_ecdsa)/len(signature_rsa)*100):.1f}%")
