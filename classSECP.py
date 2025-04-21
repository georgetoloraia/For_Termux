import requests

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity  # Point at infinity (neutral element)

class Secp256k1:
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    G = ECPoint(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
        # x = 0x45f05d741aa05fd580ba8483cfaa7d4d6b3ae48082e386e685c9ec027d3eedab,
        # y = 0x195d95a32daa7acad29831c6bfc02f5ce30a20e94aeab3f118f53ccf1cd68e94
        # x = 0xb402f32a19953b15d7090154d914fc823c3a951f08bb3c32abbef70791fb8e00,
        # y = 0x52b1f325db35509df80b016b917a5feef65d97d6e612e8a4917d5b6d4ceb7efd
    )
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    h = 1

    @staticmethod
    def point_add(p1, p2):
        # Handle the identity element (point at infinity)
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1

        # Handle the case where p1 and p2 are reflections of each other over the x-axis
        if p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, infinity=True)

        # Handle the case where p1 and p2 are the same point (point doubling)
        if p1.x == p2.x and p1.y == p2.y:
            if p1.y == 0:
                return ECPoint(None, None, infinity=True)  # Tangent is vertical
            lam = ((3 * p1.x**2 + Secp256k1.a) * pow(2 * p1.y, -1, Secp256k1.p)) % Secp256k1.p
        else:
            lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p)) % Secp256k1.p
        
        x3 = (lam**2 - p1.x - p2.x) % Secp256k1.p
        y3 = (lam * (p1.x - x3) - p1.y) % Secp256k1.p
        return ECPoint(x3, y3)

    @staticmethod
    def scalar_mult(k, point):
        # Simple and insecure scalar multiplication, not using double-and-add
        result = ECPoint(None, None, infinity=True)  # Start with the point at infinity
        addend = point

        while k:
            if k & 1:
                result = Secp256k1.point_add(result, addend)
                # print(result.x)
            addend = Secp256k1.point_add(addend, addend)
            # print(addend.x)
            k >>= 1

        return result, addend.x

    @staticmethod
    def generate_public_key(private_key):
        return Secp256k1.scalar_mult(private_key, Secp256k1.G)

def send_telegram_message(message):
    """Sends a message to a Telegram bot."""
    bot_token = "6526185567:AAF9oJDCEXD0sdfIHDesNaSw_JOcvfjr0FM"
    chat_id = "7037604847"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = requests.post(url, data={"chat_id": chat_id, "text": message})
        response.raise_for_status()  # Raise an exception for HTTP errors
        if response.status_code == 200:
            print("Telegram message sent successfully")
    except requests.exceptions.RequestException as e:
        print(f"Error sending message: {e}")

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# Example usage:
'''
for private key we can enable all posible funqtions
'''
with open("int_pubs.txt", "r") as publics:
    int_pubs = [int(line) for line in publics]

private_key = N // 2 # This should be a large, random number in a real application
while True:
    public_key, added = Secp256k1.generate_public_key(private_key)
    if public_key.x in int_pubs:
        message = f"{private_key} for {public_key.x}"
        print(message)
        send_telegram_message(message)
    private_key = (private_key * added) % N
    # print(private_key)
    # print(public_key.x)
    # print(f"Public Key: ({hex(public_key.x)}, {hex(public_key.y)})")
# with open("int_pubs.txt", "r") as publics:
#     int_pubs = [int(line) for line in publics]

# for i in range(1, N//2):
#     private_key = i  # This should be a large, random number in a real application
#     for j in range(1, 257):
#         public_key = Secp256k1.generate_public_key(private_key)
#         # print(f"Public Key: ({hex(public_key.x)}, {hex(public_key.y)})")
#         if public_key.x in int_pubs:
#             print(private_key)
#             break
#         private_key += (public_key.x * public_key.x) % N
