#! /usr/bin/env python
import fileinput
from re import M

def main():
    cont = 0
    m= -1
    data = []
    
    for line in fileinput.input():
        if cont == 0:
            n_m = line.split(",")
            m = int(n_m[1])
        else:
            data.append(int(line))
        cont= cont +1

    result = "SIM"
    aux = data[m]
    for x in data:
        if x< aux:
            result = "NÃO"

    print(result)


if __name__ == '__main__':
    main()