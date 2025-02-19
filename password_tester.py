import string
import time
import hashlib
from typing import Dict, List, Tuple
import re

class PasswordStrengthTester:
    """
    A tool for analyzing password strength and demonstrating common password vulnerabilities.
    For educational and portfolio purposes only.
    """
    
    def __init__(self):
        self.common_passwords = {
            'password', '123456', 'qwerty', 'admin', 
            'welcome', 'letmein', 'monkey', 'dragon'
        }
        
    def analyze_password(self, password: str) -> Dict[str, any]:
        """
        Performs comprehensive password strength analysis.
        
        Args:
            password: The password to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'length': len(password),
            'strength_score': 0,
            'time_to_crack': 0,
            'vulnerabilities': [],
            'suggestions': []
        }
        
        # Check basic requirements
        if len(password) < 8:
            results['vulnerabilities'].append('Password is too short')
            results['suggestions'].append('Use at least 8 characters')
            
        if len(password) < 12:
            results['suggestions'].append('Consider using at least 12 characters for better security')
            
        # Check character composition
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        if not has_upper:
            results['vulnerabilities'].append('No uppercase letters')
            results['suggestions'].append('Add uppercase letters')
            
        if not has_lower:
            results['vulnerabilities'].append('No lowercase letters')
            results['suggestions'].append('Add lowercase letters')
            
        if not has_digit:
            results['vulnerabilities'].append('No numbers')
            results['suggestions'].append('Add numbers')
            
        if not has_special:
            results['vulnerabilities'].append('No special characters')
            results['suggestions'].append('Add special characters')
            
        # Calculate entropy and approximate crack time
        entropy = self._calculate_entropy(password)
        results['entropy'] = entropy
        results['time_to_crack'] = self._estimate_crack_time(entropy)
        
        # Check for common patterns
        if self._contains_common_patterns(password):
            results['vulnerabilities'].append('Contains common patterns')
            results['suggestions'].append('Avoid keyboard patterns and common sequences')
            
        if password.lower() in self.common_passwords:
            results['vulnerabilities'].append('Commonly used password')
            results['suggestions'].append('Use a unique password')
            
        # Calculate overall strength score
        results['strength_score'] = self._calculate_strength_score(password, results)
        
        return results
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculates password entropy as a measure of randomness.
        """
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += len(string.punctuation)
            
        return len(password) * (charset_size.bit_length())
    
    def _estimate_crack_time(self, entropy: float) -> float:
        """
        Estimates time to crack based on entropy and assumed computing power.
        """
        # Assume 1 billion hashes per second for estimation
        hashes_per_second = 1_000_000_000
        possible_combinations = 2 ** entropy
        seconds_to_crack = possible_combinations / hashes_per_second
        return seconds_to_crack
    
    def _contains_common_patterns(self, password: str) -> bool:
        """
        Checks for common keyboard patterns and sequences.
        """
        common_patterns = [
            r'qwerty', r'asdfgh', r'zxcvbn',  # Keyboard patterns
            r'abcdef', r'123456', r'098765',   # Sequential patterns
            r'(.)\1{2,}'                       # Repeated characters
        ]
        
        return any(re.search(pattern, password.lower()) for pattern in common_patterns)
    
    def _calculate_strength_score(self, password: str, results: Dict) -> int:
        """
        Calculates overall password strength score (0-100).
        """
        score = 0
        
        # Length points (up to 25)
        length_score = min(len(password) * 2, 25)
        score += length_score
        
        # Character composition (up to 25)
        if any(c.isupper() for c in password): score += 6
        if any(c.islower() for c in password): score += 6
        if any(c.isdigit() for c in password): score += 6
        if any(c in string.punctuation for c in password): score += 7
        
        # Entropy bonus (up to 25)
        entropy_score = min(results['entropy'] / 4, 25)
        score += entropy_score
        
        # Deductions for vulnerabilities
        score -= len(results['vulnerabilities']) * 10
        
        return max(0, min(100, int(score)))

def demo_password_tester():
    """
    Demonstrates the usage of the PasswordStrengthTester class.
    Allows the user to input their own password for testing.
    """
    tester = PasswordStrengthTester()
    
    # Ask user for a password
    password = input("Enter a password to test: ")
    
    # Ensure the user provided a non-empty password
    if not password:
        print("Password cannot be empty. Please try again.")
        return
    
    print("\nAnalyzing password:", password)
    results = tester.analyze_password(password)
    
    # Display the results
    print(f"\nStrength Score: {results['strength_score']}/100")
    print(f"Entropy: {results['entropy']:.2f} bits")
    print(f"Estimated crack time: {results['time_to_crack']:.2e} seconds")
    
    if results['vulnerabilities']:
        print("\nVulnerabilities found:")
        for vuln in results['vulnerabilities']:
            print(f"- {vuln}")
            
    if results['suggestions']:
        print("\nSuggestions for improvement:")
        for suggestion in results['suggestions']:
            print(f"- {suggestion}")
    
if __name__ == "__main__":
    demo_password_tester()
