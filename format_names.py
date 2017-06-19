# format_names.py: transform a list of names from US census data into a Ragel pattern
import sys
names = set()
for fn in sys.argv[2:]:
    with open(fn) as f:
        for line in f:
            name = line.split()[0]
            if len(name) > 4:
                names.add(name)

sys.stdout.write("%%{\nmachine snitchd_search;\n")
sys.stdout.write("%s = (" % (sys.argv[1], ))
sys.stdout.write(
    " | ".join(
        "\"%s\"i" % (name.lower(),) for name in sorted(names)))
sys.stdout.write(");\n")
sys.stdout.write("}%%\n")
