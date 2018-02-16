#2018-02-09 SK: Utilized to generate obscure answers for secret questions.

import pyperclip

#ascii value of a char is obtained by ord() method.
# ascii for lower characters range from a at 97 to z at 122
def move_chars_by_number(answer,number_to_move):
    char_list = list(answer)
    for i in range(len(char_list)):
        cur_chr = char_list[i]
##        print('char is ' + str(cur_chr))
##        print('ascii is ' + str(ord(cur_chr)))
        if(cur_chr != ' '):
            new_char_ord = ord(cur_chr) + number_to_move;
        else:
            new_char_ord = ord(cur_chr)
        if(new_char_ord > 122):
            new_char_ord = 96 + (new_char_ord - 122)
        char_list[i] = chr(new_char_ord)
##        print('new char is ' + str(char_list[i]))

    return ''.join(char_list)

def prompt_input():
    print('Please enter: ')
    print(' 1. To shift an other string')
    print(' q. To quit')
    choice = input()
    return str(choice)

while(prompt_input() != 'q'):
    # goal is to generate a unique string for secret question answers, by shifting a
    # certain number of digits. Mark the number of digits in password software
    print('Please enter the text to shift (shift preserves space)')
    answer = input()

    print('Please enter the string to shift between 1-25')
    number_to_shift = input()
    while int(number_to_shift) < 1 or int(number_to_shift) > 25:
        print('Please enter the string to shift between 1-25')
        number_to_shift = input()


    new_str = move_chars_by_number(answer,int(number_to_shift))
    pyperclip.copy(new_str)
    print(answer + ' shifted ' + str(number_to_shift) + ' chars to right is ' + new_str)
    print('shifted string copied to clipboard')
