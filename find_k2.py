import ecdsa
from ecdsa.ellipticcurve import Point
from ecdsa import SECP256k1
from concurrent.futures import ThreadPoolExecutor

# SECP256k1 parameters
p = SECP256k1.curve.p()
a = SECP256k1.curve.a()
b = SECP256k1.curve.b()

class ECOperations:
    def __init__(self):
        self.curve = SECP256k1.curve
        self.generator = SECP256k1.generator
        self.order = SECP256k1.order

    def ec_add(self, P, Q):
        """Adds two points P and Q on the elliptic curve."""
        if P is None:
            return Q
        if Q is None:
            return P
        if P.x == Q.x and (P.y() + Q.y()) % self.curve.p() == 0:
            return None  # Point at infinity
        if P != Q:
            m = (Q.y - P.y) * pow(Q.x - P.x, -1, self.curve.p()) % self.curve.p()
        else:
            m = (3 * P.x()**2 + self.curve.a()) * pow(2 * P.y(), -1, self.curve.p()) % self.curve.p()
        x = (m**2 - P.x() - Q.x()) % self.curve.p()
        y = (m * (P.x() - x) - P.y()) % self.curve.p()
        return Point(self.curve, x, y)

    def ec_sub(self, P, Q):
        """Subtracts point Q from point P on the elliptic curve, i.e., P - Q."""
        return self.ec_add(P, Point(self.curve, Q.x, (-Q.y()) % self.curve.p()))  # R + (-Q)

    def ec_halve(self, Q):
        """Efficiently attempts to halve the point Q."""
        if Q is None:
            return None
        x, y = Q.x(), Q.y()

        # Split the range of candidates and process in parallel
        def try_halve_candidate(u_candidate):
            u3 = pow(u_candidate, 3, self.curve.p())
            a_u = (self.curve.a() * u_candidate) % self.curve.p()
            numerator = (u3 + a_u + self.curve.b()) % self.curve.p()
            try:
                v_candidate_sq = numerator % self.curve.p()
                v_candidates = self.mod_sqrt(v_candidate_sq, self.curve.p())
            except ValueError:
                return None
            for v_candidate in v_candidates:
                R = Point(self.curve, u_candidate, v_candidate)
                R_double = self.ec_add(R, R)
                if R_double.x() == x and R_double.y() == y:
                    return R
            return None

        # Use ThreadPoolExecutor to parallelize halving candidate search
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(try_halve_candidate, range(self.curve.p() // 2, self.curve.p())))

        for result in results:
            if result is not None:
                return result
        return None

    def mod_sqrt(self, n, p):
        """Efficiently computes the modular square root."""
        n %= p
        if n == 0:
            return [0]
        if pow(n, (p - 1) // 2, p) != 1:
            raise ValueError(f"No square root exists for {n} mod {p}")
        if p % 4 == 3:
            x = pow(n, (p + 1) // 4, p)
            return [x, p - x]
        # Tonelli-Shanks algorithm
        q = p - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
        c = pow(z, q, p)
        x = pow(n, (q + 1) // 2, p)
        t = pow(n, q, p)
        m = s
        while t != 1:
            i, temp = 0, t
            while temp != 1 and i < m:
                temp = pow(temp, 2, p)
                i += 1
            if i == m:
                raise ValueError("No square root exists")
            b = pow(c, 1 << (m - i - 1), p)
            x = (x * b) % p
            t = (t * b * b) % p
            c = (b * b) % p
            m = i
        return [x, p - x]

    def track_steps(self, known_x, known_y, P):
        """Track previous steps by performing subtraction and addition."""
        Q = Point(self.curve, known_x, known_y)
        steps = []

        current_point = Q
        while current_point != P:
            # Check if we can halve the point (backtrack)
            previous_point = self.ec_halve(current_point)
            if previous_point:
                steps.append(0)  # Track doubling
                current_point = previous_point
            else:
                # If halving fails, try subtraction
                Q_sub = self.ec_sub(current_point, P)
                R_halve_sub = self.ec_halve(Q_sub)
                if R_halve_sub:
                    steps.append(1)  # Track addition
                    current_point = R_halve_sub
                else:
                    raise ValueError("Cannot backtrack; invalid point")

        steps.reverse()  # Reverse to get the correct order
        k = int(''.join(map(str, steps)), 2) if steps else 0
        return k, steps


def main():
    # SECP256k1 curve parameters
    curve = SECP256k1.curve
    Gx = SECP256k1.generator.x()
    Gy = SECP256k1.generator.y()

    # Base point P (choose a valid point on the curve)
    P = Point(curve, Gx, Gy)

    x = 72244120409379604098796391927738527060634009047686252086380095014991526076380
    y = 92556313428135438087764873690409969984022593371150568216280700607151463456681
    # Recover the private key from Q
    ec_ops = ECOperations()
    recovered_k, steps = ec_ops.track_steps(x, y, P)
    message = f"Recovered private key: {recovered_k}, steps: {steps}"
    print(message)
    with open("Found.txt", "a") as found:
        found.write(message)

if __name__ == "__main__":
    main()
