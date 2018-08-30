''' WAP to accept input from user and find next prime number ''' 

def next_prime_number(input_number):
    for num in range(input_number, input_number + 100):
        if num > 1:
            for i in range(2, num):
                if(num%i) == 0:
                    print "{} is {} times of {}".format(num, num//i, i)
                    break

            else:
                return num


def main():
    input_number = int(input("Enter the number : "))
    print "Next prime number is {}".format(next_prime_number(input_number))

if __name__ == '__main__':
    main()
