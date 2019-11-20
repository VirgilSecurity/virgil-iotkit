import base64
import binascii


class UI:

    class InputCheckers:

        @classmethod
        def check_base64(cls, user_input):
            try:
                base64.b64decode(user_input)
            except binascii.Error:
                return False
            return True

        @classmethod
        def signature_input_check(cls, user_input):
            try:
                u_i = int(user_input)
            except ValueError:
                return False
            if u_i in range(1, 4294967296):
                return True

        @classmethod
        def yes_no_checker(cls, user_input):
            return user_input.upper() in ["Y", "N"]

        @staticmethod
        def tl_version_check(user_input):
            """
            Sample TL version: 0.1.30.2
            """
            user_input = user_input.split(".")
            if len(user_input) != 4:
                return False
            major, minor, patch, build = user_input
            try:
                version_parts = [int(part) for part in (major, minor, patch)]
                build = int(build)
            except ValueError:  # each part should be an integer
                return False
            if not all(part in range(0, 256) for part in version_parts):  # each part should fit uint8
                return False
            if not (0 <= build <= 4294967295):  # build should fit uint32
                return False
            return True

    def __init__(self, logger=None):
        self.__logger = logger

    def choose_from_list(self, choose_list, input_prompt, greeting_msg=None):
        """
        Get choose from user, from presented list.

        List structure:
        [
            ["String name for print in ui", object which must be choose for next use]
            ["String name for print in ui", object which must be choose for next use]
            ...
        ]

        Args:
            choose_list: Dict with various objects struct exampled above
            input_prompt: Prompt witch printed at end of list
            greeting_msg: Greeting string, printed before list

        Returns: number which represent dict key.
        """
        if greeting_msg:
            self.print_message(greeting_msg)
        if len(choose_list) == 0:
            return
        cleaned_choose_list = list()
        for key in range(len(choose_list)):
            if choose_list[key][0] == "---":
                self.print_message("\t" + "-"*10)
            else:
                cleaned_choose_list.append(choose_list[key][0])
                self.print_message("\t{0}. {1}".format(len(cleaned_choose_list), cleaned_choose_list[-1]))
        choice = self.get_user_input(input_prompt)
        try:
            choice = int(choice)
        except ValueError:
            print('Invalid value, please try again')
            if self.__logger:
                self.__logger.warning('entered invalid value at user choice action')
            return self.choose_from_list(choose_list, input_prompt, greeting_msg)
        if choice not in range(1, len(cleaned_choose_list) + 1):
            print('Invalid value, please try again')
            if self.__logger:
                self.__logger.warning('entered invalid value at user choice action')
            return self.choose_from_list(choose_list, input_prompt, greeting_msg)
        else:
            return int(choice - 1)

    def print_message(self, msg):
        print(msg)
        if self.__logger:
            self.__logger.debug(msg)

    def print_error(self, msg):
        print("[ERROR]: {}".format(msg))
        if self.__logger:
            self.__logger.error(msg)

    def print_warning(self, msg):
        print("[WARNING]: {}".format(msg))
        if self.__logger:
            self.__logger.warning(msg)

    def get_user_input(self, input_prompt, input_checker_callback=None, input_checker_msg=None, empty_allow=False):
        user_input = input(input_prompt)
        if not empty_allow:
            if not user_input:
                self.print_message("Empty input is not allowed! Please try again!")
                if self.__logger:
                    self.__logger.warning("empty input entered!")
                return self.get_user_input(input_prompt, input_checker_callback, input_checker_msg, empty_allow)
        if input_checker_callback:
            if not input_checker_callback(user_input):
                if empty_allow and user_input == "":
                    return user_input
                if not input_checker_msg:
                    self.print_message("Invalid value, please try again!")
                    if self.__logger:
                        self.__logger.warning('entered invalid value at user input')
                else:
                    self.print_message(input_checker_msg)
                    if self.__logger:
                        self.__logger.warning(input_checker_msg)
                return self.get_user_input(input_prompt, input_checker_callback, input_checker_msg, empty_allow)
        return user_input

    def get_date(self):
        while True:
            year = self.get_user_input(
                "Enter year (yyyy): ",
                input_checker_callback=lambda i: i.isdigit() and (int(i) in range(2015, 2151)),
                input_checker_msg="Only integer value from 2015 to 2150 is allowed. Please try again: ",
                empty_allow=False
            )
            month = self.get_user_input(
                "Enter month (1-12): ",
                input_checker_callback=lambda i: i.isdigit() and (int(i) in range(1, 13)),
                input_checker_msg="Only integer value from 1 to 12 is allowed. Please try again: ",
                empty_allow=False
            )
            day = self.get_user_input(
                "Enter day (1-31): ",
                input_checker_callback=lambda i: i.isdigit() and (int(i) in range(1, 32)),
                input_checker_msg="Only integer value from 1 to 31 is allowed. Please try again: ",
                empty_allow=False
            )

            confirmed = self.get_user_input(
                "Year: %s, Month: %s, Day: %s. Confirm? [y/n] " % (year, month, day),
                input_checker_callback=self.InputCheckers.yes_no_checker,
                input_checker_msg="Allowed answers [y/n]. Please try again: ",
                empty_allow=False
            ).upper()
            if confirmed == "Y":
                return int(year), int(month), int(day)
