

class UI(object):

    def __init__(self):
        pass

    def choose_from_list(self, choose_dict, input_prompt, greating_msg=None):
        """
        Get choose from user, from presented dict.

        Dict structure:
        {
            1: ["String name for print in ui", object which must be choose for next use]
            2: ["String name for print in ui", object which must be choose for next use]
            ...
        }

        Args:
            choose_dict: Dict with various objects struct exampled above
            input_prompt: Prompt witch printed at end of list
            greating_msg: Greating string, printed before list

        Returns: number which represent dict key.
        """
        if greating_msg:
            self.print_message(greating_msg)
        for key in choose_dict.keys():
            self.print_message("\t{0}. {1}".format(key, choose_dict[key][0]))
        choice = self.get_user_input(input_prompt)
        try:
            choice = int(choice)
        except ValueError:
            print('Invalid value, please try again')
            return self.choose_from_list(choose_dict, input_prompt, greating_msg)
        if choice not in range(1, len(choose_dict.keys()) + 1):
            print('Invalid value, please try again')
            return self.choose_from_list(choose_dict, input_prompt, greating_msg)
        else:
            return choice

    def print_message(self, msg):
        print(msg)

    def print_error(self, msg):
        print("[ERROR]: {}".format(msg))

    def get_password_pair(self):
        pass

    def get_user_input(self, input_prompt, input_checker_callback=None, input_checker_msg=None, empty_allow=False):
        user_input = input(input_prompt)
        if not empty_allow:
            if not user_input:
                self.print_message("Empty input not allowed! Please try again!")
                return self.get_user_input(input_prompt, input_checker_callback, input_checker_msg, empty_allow)
        if input_checker_callback:
            if not input_checker_callback(user_input):
                if empty_allow and user_input == "":
                    return user_input
                if not input_checker_msg:
                    self.print_message("The entered value does not match, Please try again!")
                else:
                    self.print_message(input_checker_msg)
                return self.get_user_input(input_prompt, input_checker_callback, input_checker_msg, empty_allow)
        return user_input

    def get_password(self):
        pass
