import fcntl
import os
import re
import subprocess
from threading import Thread
from time import sleep

from waiting import wait, TimeoutExpired


class CmdSubProcess:
    def __init__(self, cmd, env_vars=None, logger=None, print_output=False):
        self.cmd = cmd
        custom_env_vars = os.environ.copy()
        if env_vars:
            custom_env_vars.update(env_vars)
        self.env_vars = custom_env_vars
        self.pid = None
        self.proc = None
        self.output = []  # list with lines from stdout
        self.errors = []  # list with lines from stderr
        self.stdout_offset = 0  # previous lines will be ignored in search

        self._return_code = None
        self._killed = False  # whether running process was stopped by .kill()
        self._logger = logger
        self._print_output = print_output

    @property
    def return_code(self):
        if self.proc is None:  # in case if process has not been started yet
            return self._return_code
        if self._return_code is None:
            self._return_code = self.proc.poll()
        return self._return_code

    def run(self):
        if self._logger:
            self._logger.debug("Run: %s" % self.cmd)

        self.proc = subprocess.Popen(self.cmd,
                                     shell=True,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     env=self.env_vars
                                     )
        self.pid = self.proc.pid

        # Enable non-blocking read (Unix only!)
        fcntl.fcntl(self.proc.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(self.proc.stderr.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

        # Process output
        out_iterator = _OutputIterator(self.proc.stdout)
        err_iterator = _OutputIterator(self.proc.stderr)
        self._process_output(out_iterator, err_iterator)

        if self._logger:
            self._logger.debug("EXIT CODE: %s" % self.return_code)

    def _process_output(self, out_iter, err_iter):
        while not all([self.return_code is not None, out_iter.is_empty, err_iter.is_empty]):
            # stop further processing if process has been terminated from code
            if self._killed:
                break
            out_line, err_line = next(out_iter), next(err_iter)
            if not out_line and not err_line:
                sleep(0.01)
                continue
            if out_line:
                self._process_line(out_line)
            if err_line:
                self._process_line(err_line, from_std_err=True)
        else:
            # do final check for missed output
            try:
                out_line = wait(lambda: next(out_iter), timeout_seconds=0.05)
                self._process_line(out_line)
            except TimeoutExpired:
                out_line = None
            try:
                err_line = wait(lambda: next(err_iter), timeout_seconds=0.05)
                self._process_line(err_line, from_std_err=True)
            except TimeoutExpired:
                err_line = None

            # If unprocessed output was observed - run processing again
            if out_line or err_line:
                self._process_output(out_iter, err_iter)

    def run_in_thread(self):
        worker = Thread(target=self.run, daemon=True)
        worker.start()

    def send_to_stdin(self, input_):
        """
        :param input_: string or bytes
        """
        # Send input
        self.update_stdout_offset()
        if isinstance(input_, str):
            input_ = bytes(input_, "ascii")
        input_ += b"\n"
        self.proc.stdin.write(input_)
        self.proc.stdin.flush()

        # Log
        msg = "sent to stdin: %s" % str(input_)
        if self._logger:
            self._logger.info(msg)
        if self._print_output:
            print(msg)

    def kill(self):
        # if process is still running - send `SIGKILL` signal
        if self._return_code is None:
            if self._logger:
                self._logger.info("KILLED (SIGKILL)")
            self._killed = True
            self.proc.kill()

    def terminate(self):
        # if process is still running - send `SIGTERM` status
        if self._return_code is None:
            if self._logger:
                self._logger.info("TERMINATED (SIGTERM)")
            self.proc.terminate()

    def update_stdout_offset(self, offset=None):
        """
        Set offset to current output length
        """
        if offset is not None:
            self.stdout_offset = offset
        self.stdout_offset = len(self.output)

    def wait_for_output(self, text, timeout_seconds=10, regex=False, **kwargs):
        """
        :return: line with text or raises TimeoutExpired exception
        """
        seen = self.stdout_offset

        def finder():
            nonlocal seen
            for line in self.output[seen:]:
                if regex:
                    match = re.search(text, line)
                else:
                    match = text in line
                if match:
                    return line
                seen += 1
            return ""

        waiting_for = 'Text "%s" is present inside output of "%s" cmd' % (text, self.cmd)
        return wait(
            lambda: self.output and finder(), timeout_seconds, waiting_for=waiting_for, sleep_seconds=0.01,  **kwargs
        )

    def _process_line(self, line, from_std_err=False):
        if self._print_output:
            print(line)
        if self._logger:
            if from_std_err:
                self._logger.error(line)
            else:
                self._logger.debug(line)
        if from_std_err:
            self.errors.append(line)
        else:
            self.output.append(line)


class _OutputIterator:
    """
    Simple iterator over non-blocking std object
    """
    def __init__(self, std):
        self._std = std
        self.is_empty = False

    def __iter__(self):
        return self

    def __next__(self):
        line = self._std.readline()
        line = line.decode("utf-8")
        if line:
            self.is_empty = False
        else:
            self.is_empty = True
        return line.strip()
