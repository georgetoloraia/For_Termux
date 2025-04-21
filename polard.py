import random
from collections import defaultdict
import multiprocessing

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

class Secp256k1:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    G = ECPoint(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    h = 1

    @staticmethod
    def point_add(p1, p2):
        """
        Point addition formula for SECP256k1 elliptic curve
        p1, p2: ECPoint objects
        Returns: ECPoint object
        """
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1

        # If the points are the same, use point doubling
        if p1.x == p2.x and p1.y == p2.y:
            if p1.y == 0:
                return ECPoint(None, None, infinity=True)  # Point at infinity
            lam = ((3 * p1.x**2 + Secp256k1.a) * pow(2 * p1.y, -1, Secp256k1.p)) % Secp256k1.p
        elif p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, infinity=True)  # Points are reflections of each other

        else:  # General case for different points
            lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p)) % Secp256k1.p

        x3 = (lam**2 - p1.x - p2.x) % Secp256k1.p
        y3 = (lam * (p1.x - x3) - p1.y) % Secp256k1.p

        return ECPoint(x3, y3)

    @staticmethod
    def scalar_mult(k, point):
        """
        Scalar multiplication using the double-and-add method
        k: Scalar (private key)
        point: ECPoint (base point or result point)
        Returns: ECPoint (result of k * point)
        """
        result = ECPoint(None, None, infinity=True)  # Identity element
        addend = point

        while k:
            if k & 1:
                result = Secp256k1.point_add(result, addend)
            addend = Secp256k1.point_add(addend, addend)  # Double the point
            k >>= 1

        return result

    @staticmethod
    def generate_public_key(private_key):
        return Secp256k1.scalar_mult(private_key, Secp256k1.G)

    @staticmethod
    def hex_to_point(pub_key_hex):
        """
        Converts an uncompressed public key (hex string) to an ECPoint.
        The format is:
        04 | x-coordinate (32 bytes) | y-coordinate (32 bytes)
        """
        if pub_key_hex[:2] != "04":  # Ensure it's uncompressed format
            raise ValueError("Public key is not in uncompressed format.")
        
        x_hex = pub_key_hex[2:66]  # x-coordinate (32 bytes)
        y_hex = pub_key_hex[66:]   # y-coordinate (32 bytes)
        
        x = int(x_hex, 16)  # Convert hex to integer
        y = int(y_hex, 16)  # Convert hex to integer
        
        return ECPoint(x, y)

    @staticmethod
    def pollards_rho_search(target_public_key):
        """
        Pollard's Rho algorithm for discrete logarithm to find the private key
        corresponding to the given public key.
        """
        # Start with some initial values
        x1, y1 = Secp256k1.G.x, Secp256k1.G.y  # The base point
        x2, y2 = Secp256k1.G.x, Secp256k1.G.y  # Another point for iteration
        a1, b1 = 0, 1  # Coefficients for the first point
        a2, b2 = 0, 1  # Coefficients for the second point

        # Create a map to store intermediate results
        visited = defaultdict(list)

        # Arbitrary number of iterations to limit search space
        for _ in range(2**32):
            i = random.randint(1, N)
            # Generate a random path using pseudo-random function
            if i % 3 == 0:
                point1 = Secp256k1.point_add(ECPoint(x1, y1), Secp256k1.G)
                x1, y1 = point1.x, point1.y
                a1 = (a1 + 1) % Secp256k1.n
            elif i % 3 == 1:
                point2 = Secp256k1.point_add(ECPoint(x2, y2), Secp256k1.G)
                x2, y2 = point2.x, point2.y
                a2 = (a2 + 1) % Secp256k1.n
            else:
                point1 = Secp256k1.point_add(ECPoint(x1, y1), ECPoint(x2, y2))
                x1, y1 = point1.x, point1.y
                a1, b1 = (a1 + a2) % Secp256k1.n, (b1 + b2) % Secp256k1.n

            # Check for a collision by storing results in the map
            if (x1, y1) in visited:
                for (x, y, a, b) in visited[(x1, y1)]:
                    if x == target_public_key.x and y == target_public_key.y:
                        # Collision found, use the coefficients to find the private key
                        d = (a - a1) * pow(b1 - b, -1, Secp256k1.n) % Secp256k1.n
                        print(f"Private Key found: {d}")
                        return d
                visited[(x1, y1)].append((x1, y1, a1, b1))

        # print("Private key not found.")
        return None

def search_for_keys(public_keys):
    """
    Searches for the private keys corresponding to multiple public keys.
    Uses multiprocessing to search in parallel.
    """
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        pool.map(Secp256k1.pollards_rho_search, public_keys)

# Example usage:
with open("pubs.txt", "r") as publics:
    public_keys = []
    for line in publics:
        pub_key_hex = line.strip()  # Public key in hex format from file
        try:
            # Convert the hex public key to ECPoint (x, y coordinates)
            target_public_key = Secp256k1.hex_to_point(pub_key_hex)
            public_keys.append(target_public_key)
        except ValueError as e:
            print(f"Error: {e}")

    # Search for private keys corresponding to all public keys in parallel
    search_for_keys(public_keys)
