''' WAP to count occurance of number in given range '''
''' e.g. pass 9 and range of 0 to 100 - it will return total '''
''' occurances of 9 number in 0 to 100 '''

check = raw_input("Enter number to be checked : ")
a = int(raw_input("Enter Range Start :  "))
b = int(raw_input("Enter Range End : "))
count = 0
for a in range(a, b):
    number_string = str(a)
    for ch in number_string:
        print "{}   {}".format(ch, a)
        if ch == check:
            count = count + 1

print "Total number {} in {} is {}".format(check, b, count)
