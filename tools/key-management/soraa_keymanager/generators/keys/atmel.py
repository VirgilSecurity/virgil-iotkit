class Atmel(object):

    def __init__(self, ui, atmel):
        self._ui = ui
        self._atmel = atmel

    def _a_check(self, atmel_ops_status):
        """
        Atmel operation checker. Check status of operation.

        Args:
            atmel_ops_status:  atmel operation output
        Returns:
            In error case print error and return 0
            In success return, object of function return
        """
        if not atmel_ops_status[0]:
            self._ui.print_error(atmel_ops_status[1])
            return 0
        return atmel_ops_status[1]
