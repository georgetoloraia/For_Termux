import ecdsa

# SECP256K1 parameters
N = ecdsa.SECP256k1.order
# print(N)

# მოცემული რიცხვები
G_x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
G_y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
pub_x = 46833799212576611471711417854818141128240043280360231002189938627535641370294

# გამყოფი X-ის გამოთვლა
X = pub_x / G_x

# ჯამის გაგება
xPLIUSx = (pub_x / (G_x + G_y)) % N
# xPLIUSx = xPLIUSx * 0.8504989560237591

print(f"X = {X}")
print(f"X + X / 0.8504989560237591 = {xPLIUSx}")

with open("minus.txt", "a") as george:
    for _ in range(130000):
        G_y += G_y
        m = G_y % N
        george.write(f"{m}\n")
