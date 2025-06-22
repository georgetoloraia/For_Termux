# def main():
#     with open("allpubs.txt", "r") as r:
#         pubs = [line for line in r]

#     with open("target_pub.txt", "w") as a:
#         i = 1
#         for pub in pubs:
#             res = f"{pub},Wallet{i}"
#             a.write(res)
#             i += 1

# main()


def main():
    with open("allpubs.txt", "r") as r:
        pubs = [line.strip() for line in r]  # remove newline characters

    with open("target_pub.txt", "w") as a:
        for i, pub in enumerate(pubs, start=1):
            res = f"{pub},wallet{i}\n"  # ensure newline after each entry
            a.write(res)

main()
