import tempfile
import cups


class PrinterController(object):

    def __init__(self, ui):
        self.__ui = ui
        self.conn = cups.Connection()

    def __choose_printer(self):
        self.__ui.print_message("Searching printers...")
        printers = self.conn.getPrinters()
        self.__ui.print_message("Search complete.")
        printer_choose_list = list()
        for printer_key in printers.keys():
            printer_choose_list.append(
                [
                    printers[printer_key]["printer-info"],
                    printer_key
                 ]
            )
        if not printer_choose_list:
            self.__ui.print_error(
                "Can't find any connected printers, please connect and configure printer to print the RestorePaper!"
            )
            printer_rescan = self.__ui.get_user_input(
                "Rescan printers? [Y]:",
                input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                input_checker_msg="Allowed answer [y], Please try again: ",
                empty_allow=True
            ).upper()
            if printer_rescan in ["Y", ""]:
                return self.__choose_printer()
        user_choice = self.__ui.choose_from_list(
            printer_choose_list,
            "Please enter printer option number: ",
            "Printers: "
        )
        return printer_choose_list[user_choice][1]

    def send_to_printer(self, key_info):
        printer = self.__choose_printer()

        if not printer:
            return

        key_info_path = tempfile.NamedTemporaryFile("w+")

        key_info_path.write(
            "{key_type} key: {recovery_key}\ncomment: {comment}".format(
                key_type=key_info["type"],
                recovery_key=key_info["key"],
                comment=key_info["comment"]
            )
        )
        key_info_path.flush()
        self.conn.printFile(printer, key_info_path.name, "{}_info_print".format(key_info["type"]), {"media": "A4", "fit-to-page": "true"})
        key_info_path.close()
        print_ok = self.__ui.get_user_input(
            "Is the printing correct? [y/n]:",
            input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
            input_checker_msg="Allowed answers [y/n], Please try again: ",
            empty_allow=False
        ).upper()
        if print_ok == "Y":
            return
        else:
            try_again = self.__ui.get_user_input(
                "Print again? [y/n]:",
                input_checker_callback=self.__ui.InputCheckers.yes_no_checker,
                input_checker_msg="Allowed answers [y/n], Please try again: ",
                empty_allow=False
            ).upper()
            if try_again == "Y":
                self.send_to_printer(key_info)
            else:
                return
