

print "    |   |   "
print "---|---|---"
print "---|---|---"
print "    |   |   "

def square(x): return x * x
def cube(x): return x * x * x

def print_result(x, func):
    """recieve a function and execute it and return result"""
    return func(x)

do_square = square     # assigning square function to a variable
do_cube = cube         # assigning cube function to a variable

res = print_result(5, do_square)   # passing function to another function
print res
res = print_result(5, do_cube)
print res
