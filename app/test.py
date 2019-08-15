
from datetime import date
from threading import Thread
from time import sleep
def delete_txt():
    while True:
        sleep(86400)
        with open('fridge1.txt') as f1, open('fridge2.txt') as f2:
            lst1_date_ = f1.read().splitlines()
            lst2_date_ = f2.read().splitlines()
            if lst1_date_:
                lst1_date = lst1_date_[2].split('-')
                date_time1 = str(date(int(lst1_date[0]), int(lst1_date[1][1:]), int(lst1_date[2])) - date.today())[:1]
                if date_time1 == '-':
                    with open('fridge1.txt', 'w') as fw1:
                        fw1.write('')
            if lst2_date_:
                lst2_date = lst2_date_[2].split('-')
                date_time2 = str(date(int(lst2_date[0]), int(lst2_date[1][1:]), int(lst2_date[2])) - date.today())[:1]
                if date_time2 == '-':
                    with open('fridge2.txt', 'w') as fw2:
                        fw2.write('')
delete = Thread(target=delete_txt)
delete.start()

print('aaaa')