import subprocess
import sys


class CmdSubProcess(object):

    def __init__(self, cmd, print_output=False, debug=False, output_pipe=None):
        self.cmd = cmd
        self.pid = None
        self.proc = None
        self.debug = debug
        self.print_output = print_output
        self.output = []
        self.output_pipe = output_pipe
        self.return_code = None

    def run(self):
        if self.debug:
            print("Run: {}".format(self.cmd))

        self.proc = subprocess.Popen("exec " + self.cmd,
                                     shell=True,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT
                                     )
        self.pid = self.proc.pid
        while True:
            try:
                if sys.version_info.major == 3:
                    line = self.proc.stdout.__next__()
                    line = line.decode("utf-8")

                else:
                    line = self.proc.stdout.next()

                line = line.rstrip()
                if self.print_output or self.debug:
                    print(line)
                self.output.append(line)

                if self.output_pipe:
                    self.output_pipe.put(line)

            except StopIteration:
                break

        self.proc.wait()
        self.return_code = self.proc.returncode
        if self.output_pipe:
            # ensure that pipe is closed
            try:
                self.output_pipe.task_done()
            except ValueError:
                pass

    def kill(self):
        self.proc.terminate()
