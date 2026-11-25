"""Repeated loop checks reuse the two source-level comparison elements."""
def advance(value,limit):
    count=0
    while 0 < value < limit:
        count+=1
        value+=1
    return count
