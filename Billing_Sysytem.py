"""    ====== Discount Sceme ======
        Upto 1000 Rs.       -  No Discount
        1000 to 1999        -  10% Discount
        2000 to 4999        -  20% Discount
        5000 and Above    -  30% Discount """

"""WAP to calculate total discount on final billing based on Above slabs"""

Slab_20_Fix_Discount = 600
Slab_10_Fix_Discount = 100

def check_slab(amount):

    if amount > 5000:
        diff = amount - 5000
        discount_applicable = diff * 0.3
        my_dict = {"Slab30":discount_applicable}
        return my_dict
    
    elif amount > 2000 and amount <= 5000:
        diff = amount - 2000
        discount_applicable = diff * 0.2
        my_dict = {"Slab20":discount_applicable}
        return my_dict
    
    elif amount > 1000 and amount <= 2000:
        diff = amount - 1000
        discount_applicable = diff * 0.1
        my_dict = {"Slab10":discount_applicable}
        return my_dict
    elif amount <= 1000:
        discount_applicable = 0
        my_dict = {"NoSlab":discount_applicable}
        return my_dict

print(__doc__)
print "\n"
slab = dict()
amount = int(raw_input("Enter total amount  : "))
slab = check_slab(amount)

for k, v in slab.iteritems():
    if k == "Slab30":
        discount = v + Slab_20_Fix_Discount + Slab_10_Fix_Discount
    elif k == "Slab20":
        discount = v + Slab_10_Fix_Discount
    elif k == "Slab10":
        discount = v
    elif k == "NoSlab":
        discount = v

billing_amount = amount - discount
print "\nDiscount = {} INR".format(discount)
print "\nBilling Amount = {} INR".format(billing_amount)
        
