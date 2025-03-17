'''A python script that extracts and displays information from an SSH key file.
The script can handle both private and public keys in OpenSSH and PEM formats.'''
'''Author: Joseph Chissom Ofonagoro & Assistant'''


#!/usr/bin/env python3
import os
import base64
import binascii
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ed25519, ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

def extract_ssh_key_info(key_path, password=None):
    """
    Extract and display information from an SSH key file.
    
    Args:
        key_path (str): Path to the SSH key file
        password (bytes, optional): Password to decrypt the key if encrypted
    
    Returns:
        dict: Information about the SSH key
    """
    try:
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        # Store the original key data
        try:
            original_text = key_data.decode('utf-8')
        except UnicodeDecodeError:
            original_text = "Binary content (cannot display)"
            
        # Try to determine if it's a private or public key
        key_info = {
            "file_path": key_path, 
            "file_size": os.path.getsize(key_path),
            "original_content": original_text
        }
        
        key_obj = None
        try:
            # First try as private key without password
            key = load_ssh_private_key(key_data, password=password)
            key_info["type"] = "SSH private key"
            key_info["encrypted"] = (password is not None)
            key_obj = key
            
            # Extract key-specific information
            if isinstance(key, rsa.RSAPrivateKey):
                key_info["algorithm"] = "RSA"
                key_info["key_size"] = key.key_size
                key_info["public_exponent"] = key.public_key().public_numbers().e
            elif isinstance(key, dsa.DSAPrivateKey):
                key_info["algorithm"] = "DSA"
                key_info["key_size"] = key.key_size
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                key_info["algorithm"] = "ECDSA"
                key_info["curve"] = key.curve.name
            elif isinstance(key, ed25519.Ed25519PrivateKey):
                key_info["algorithm"] = "Ed25519"
            
        except Exception:
            try:
                # Try as private key in PEM format
                key = load_pem_private_key(key_data, password=password)
                key_info["type"] = "PEM private key"
                key_info["encrypted"] = (password is not None)
                key_obj = key
                
                # Extract key-specific information
                if isinstance(key, rsa.RSAPrivateKey):
                    key_info["algorithm"] = "RSA"
                    key_info["key_size"] = key.key_size
                    key_info["public_exponent"] = key.public_key().public_numbers().e
                elif isinstance(key, dsa.DSAPrivateKey):
                    key_info["algorithm"] = "DSA"
                    key_info["key_size"] = key.key_size
                elif isinstance(key, ec.EllipticCurvePrivateKey):
                    key_info["algorithm"] = "ECDSA"
                    key_info["curve"] = key.curve.name
                elif isinstance(key, ed25519.Ed25519PrivateKey):
                    key_info["algorithm"] = "Ed25519"
                    
            except Exception:
                try:
                    # Try as public key
                    key = load_ssh_public_key(key_data)
                    key_info["type"] = "SSH public key"
                    key_obj = key
                    
                    # Extract key-specific information
                    if isinstance(key, rsa.RSAPublicKey):
                        key_info["algorithm"] = "RSA"
                        key_info["key_size"] = key.key_size
                        key_info["public_exponent"] = key.public_numbers().e
                    elif isinstance(key, dsa.DSAPublicKey):
                        key_info["algorithm"] = "DSA"
                        key_info["key_size"] = key.key_size
                    elif isinstance(key, ec.EllipticCurvePublicKey):
                        key_info["algorithm"] = "ECDSA"
                        key_info["curve"] = key.curve.name
                    elif isinstance(key, ed25519.Ed25519PublicKey):
                        key_info["algorithm"] = "Ed25519"
                
                except Exception:
                    # If it's a public key in authorized_keys format
                    try:
                        lines = key_data.decode('utf-8').strip().split('\n')
                        for line in lines:
                            if line.strip() and not line.startswith('#'):
                                parts = line.split()
                                if len(parts) >= 2:
                                    key_info["type"] = "OpenSSH public key"
                                    key_info["algorithm"] = parts[0]
                                    key_info["key_data"] = parts[1]
                                    if len(parts) >= 3:
                                        key_info["comment"] = parts[2]
                                    break
                    except Exception:
                        key_info["type"] = "Unknown key format"
        
        # Extract public key in OpenSSH format if we have a key object
        if key_obj is not None:
            try:
                if "type" in key_info and "private" in key_info["type"].lower():
                    # Get public key from private key
                    public_key = key_obj.public_key()
                    public_key_bytes = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                    key_info["public_key"] = public_key_bytes.decode('utf-8')
                else:
                    # It's already a public key
                    public_key_bytes = key_obj.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
                    key_info["public_key"] = public_key_bytes.decode('utf-8')
            except Exception as e:
                key_info["public_key_error"] = str(e)
        
        # Calculate fingerprint if possible
        if "key_data" in key_info:
            try:
                raw_key = base64.b64decode(key_info["key_data"])
                fingerprint = binascii.hexlify(raw_key).decode('ascii')
                key_info["fingerprint"] = fingerprint
            except Exception:
                pass
                
        return key_info
        
    except FileNotFoundError:
        return {"error": f"File not found: {key_path}"}
    except PermissionError:
        return {"error": f"Permission denied: {key_path}"}
    except Exception as e:
        return {"error": str(e)}

def format_output(key_info):
    """Format key information for display"""
    output = []
    output.append("SSH KEY INFORMATION")
    output.append("=" * 50)
    
    # First display key metadata
    for key, value in key_info.items():
        if key == "original_content":
            continue  # Skip for now, we'll show it at the end
        elif key == "key_data":
            # Truncate long base64 data
            output.append(f"{key.replace('_', ' ').title()}: {value[:20]}...{value[-20:]} (truncated)")
        elif key == "fingerprint":
            # Format fingerprint in blocks
            fingerprint = value
            formatted = ':'.join(fingerprint[i:i+2] for i in range(0, min(40, len(fingerprint)), 2))
            output.append(f"{key.replace('_', ' ').title()}: {formatted}...")
        else:
            output.append(f"{key.replace('_', ' ').title()}: {value}")
    
    # Display the actual key content
    output.append("\nORIGINAL KEY CONTENT")
    output.append("=" * 50)
    output.append(key_info.get("original_content", "No content available"))
    
    return '\n'.join(output)

def main():
    print("SSH Key Information Extractor")
    print("=" * 30)
    
    while True:
        # Get key file path from user
        key_file = input("\nEnter the path to your SSH key file (or 'exit' to quit): ").strip()
        
        if key_file.lower() == 'exit':
            print("Exiting program.")
            break
            
        # Check if password is needed
        use_password = input("Is the key encrypted with a password? (y/n): ").strip().lower()
        password_bytes = None
        
        if use_password.startswith('y'):
            import getpass
            password = getpass.getpass("Enter password: ")
            password_bytes = password.encode()
        
        # Process the key
        key_info = extract_ssh_key_info(key_file, password_bytes)
        print("\n" + format_output(key_info))
        
        # Ask if user wants to analyze another key
        another = input("\nAnalyze another key? (y/n): ").strip().lower()
        if not another.startswith('y'):
            print("Exiting program.")
            break

if __name__ == "__main__":
    main()