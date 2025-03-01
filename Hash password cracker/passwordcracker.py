import hashlib
import argparse
from typing import Optional, List
import time

class PasswordCracker:
    """A simple password hash cracker supporting multiple hash algorithms."""
    
    def __init__(self, hash_type: str = "md5"):
        """
        Initialize the password cracker with a specific hash algorithm.
        
        Args:
            hash_type: The hash algorithm to use (md5, sha1, sha256, sha512)
        """
        self.hash_type = hash_type.lower()
        self.algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }
        
        if self.hash_type not in self.algorithms:
            raise ValueError(f"Unsupported hash type: {hash_type}. Supported types: {', '.join(self.algorithms.keys())}")
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using the configured algorithm.
        
        Args:
            password: The password to hash
            
        Returns:
            The hexadecimal digest of the hash
        """
        hash_obj = self.algorithms[self.hash_type]()
        hash_obj.update(password.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def dictionary_attack(self, target_hash: str, wordlist_file: str, verbose: bool = False) -> Optional[str]:
        """
        Perform a dictionary attack using a wordlist file.
        
        Args:
            target_hash: The hash to crack
            wordlist_file: Path to a file containing password candidates (one per line)
            verbose: Whether to print progress information
            
        Returns:
            The cracked password if successful, None otherwise
        """
        start_time = time.time()
        attempts = 0
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    attempts += 1
                    
                    if verbose and attempts % 1000 == 0:
                        elapsed = time.time() - start_time
                        print(f"Tried {attempts} passwords... ({attempts/elapsed:.0f} passwords/sec)")
                    
                    if self.hash_password(password) == target_hash:
                        elapsed = time.time() - start_time
                        if verbose:
                            print(f"\nPassword found after {attempts} attempts ({elapsed:.2f} seconds)")
                        return password
        except FileNotFoundError:
            print(f"Error: Wordlist file '{wordlist_file}' not found.")
            return None
            
        elapsed = time.time() - start_time
        if verbose:
            print(f"\nAttack finished after {attempts} attempts ({elapsed:.2f} seconds)")
        return None
    
    def brute_force(self, target_hash: str, charset: str, max_length: int, verbose: bool = False) -> Optional[str]:
        """
        Perform a brute force attack trying all possible combinations.
        
        Args:
            target_hash: The hash to crack
            charset: String containing characters to use for brute force
            max_length: Maximum password length to try
            verbose: Whether to print progress information
            
        Returns:
            The cracked password if successful, None otherwise
        """
        start_time = time.time()
        attempts = 0
        
        def generate_passwords(current: str, length: int):
            nonlocal attempts
            
            if length == 0:
                attempts += 1
                if verbose and attempts % 100000 == 0:
                    elapsed = time.time() - start_time
                    print(f"Tried {attempts} passwords... ({attempts/elapsed:.0f} passwords/sec)")
                    
                if self.hash_password(current) == target_hash:
                    return current
                return None
            
            for char in charset:
                result = generate_passwords(current + char, length - 1)
                if result:
                    return result
            
            return None
        
        for length in range(1, max_length + 1):
            if verbose:
                print(f"Trying passwords of length {length}...")
            
            result = generate_passwords("", length)
            if result:
                elapsed = time.time() - start_time
                if verbose:
                    print(f"\nPassword found after {attempts} attempts ({elapsed:.2f} seconds)")
                return result
        
        elapsed = time.time() - start_time
        if verbose:
            print(f"\nAttack finished after {attempts} attempts ({elapsed:.2f} seconds)")
        return None


def main():
    parser = argparse.ArgumentParser(description="Simple Password Hash Cracker")
    parser.add_argument("hash", help="The hash to crack")
    parser.add_argument("--type", choices=["md5", "sha1", "sha256", "sha512"], default="md5",
                        help="Hash algorithm type (default: md5)")
    parser.add_argument("--wordlist", help="Path to wordlist file for dictionary attack")
    parser.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz", 
                        help="Character set for brute force attack (default: lowercase letters)")
    parser.add_argument("--max-length", type=int, default=4,
                        help="Maximum password length for brute force attack (default: 4)")
    parser.add_argument("--verbose", action="store_true", help="Print progress information")
    
    args = parser.parse_args()
    
    cracker = PasswordCracker(args.type)
    result = None
    
    if args.wordlist:
        print(f"Starting dictionary attack using wordlist: {args.wordlist}")
        result = cracker.dictionary_attack(args.hash, args.wordlist, args.verbose)
    else:
        print(f"Starting brute force attack (max length: {args.max_length}, charset: {args.charset})")
        result = cracker.brute_force(args.hash, args.charset, args.max_length, args.verbose)
    
    if result:
        print(f"Success! The password is: {result}")
    else:
        print("Password not found.")


if __name__ == "__main__":
    main()