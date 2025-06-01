# Open input and output files
with open("allpubs.txt", "r") as infile, open("only_x.txt", "w") as outfile:
    for line in infile:
        line = line.strip()
        if not line:
            continue  # Skip empty lines
        x_str = line.split(",")[0]  # Get the first number
        x_int = int(x_str)          # Convert to integer
        x_hex = hex(x_int)[2:]      # Convert to hex and remove '0x'
        outfile.write(x_hex + "\n") # Write to output
