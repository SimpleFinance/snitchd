# format_ach.py: transform the FedACHdir.txt (ACH routing number DB) into a Ragel pattern
import sys
routing_nums = set()
for fn in sys.argv[2:]:
    with open(fn) as f:
        for line in f:
            routing_nums.add(line[:9])

sys.stdout.write("%%{\nmachine snitchd_search;\n")
sys.stdout.write("%s = (" % (sys.argv[1], ))
sys.stdout.write(
    " | ".join(
        "\"%s\"" % (num, ) for num in sorted(routing_nums)))
sys.stdout.write(");\n")
sys.stdout.write("}%%\n")
