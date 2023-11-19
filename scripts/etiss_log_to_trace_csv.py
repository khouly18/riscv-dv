"""
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Convert etiss simulation log to standard riscv instruction trace format
"""

import argparse
import os
import re
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from riscv_trace_csv import *
from lib import *

INSTR_RE = re.compile(
    r'0x(?P<pc>[0-9a-fA-F]{16}):\s(?P<instr>[a-zA-Z.]+?)\s#\s' \
     '0x(?P<bin>[0-9a-fA-F]{8})\s\[rd=(?P<rd_indx>\d+)(?:\s\|\s)?' \
     '(?P<op1>\w{2}\d|\w{3}|\w{5})?(?:=)?(?P<op1_val>\d+)?(?:\s\|\s)?(?P<op2>\w{2}\d|\w{3}|\w{5})?' \
     '(?:=)?(?P<op2_val>\d+)?(?:\s\|\s)?(?P<op3>\w{2}\d|\w{3}|\w{5})?(?:=)?(?P<op3_val>\d+)?\]')

C_INSTR_RE = re.compile(r'0x(?P<pc>[0-9a-fA-F]{16}):\s(?P<instr>[a-zA-Z0-9.]+?)\s#\s' \
                      '0x(?P<bin>[0-9a-fA-F]{4})\s')

RD_VAL_RE = re.compile(r'X\[(?P<rd_indx>\d+)\]=(?P<rd_val>[0-9a-fA-F]+)')


def assem_str(result_in):
    ass_str = result_in.group('instr') + ' rd'
    for i in range(5, result_in.lastindex + 1):
        if result_in.group(i):
           if result_in.group(i).isdigit():
              continue
           else:          
              ass_str = ass_str + ', '
              if result_in.group(i) == 'imm':
                 i = i+1
                 ass_str = ass_str + result_in.group(i)
              else:
                 ass_str = ass_str + result_in.group(i)
    return ass_str
          
def illegal_instr(instr):
    result = (instr == 'cnop') or (instr == 'cswsp') or (instr == 'csw') or (instr == 'cj') or (instr == 'cjal') or (instr == 'cjr') or (instr == 'cjalr') or (instr == 'cbeqz') or (instr == 'cbnez') or (instr == 'cebreak') or (instr == 'beq') or (instr == 'bge') or (instr == 'bgeu') or (instr == 'blt') or (instr == 'bltu') or (instr == 'bne') or (instr == 'jal') or (instr == 'jalr') or (instr == 'sb') or (instr == 'sd') or (instr == 'sh') or (instr == 'sw')
    return (not result)
def illegal_instr_full(instr):
    result = (instr == 'jalr') or (instr == 'csrrw')
    return result


LOGGER = logging.getLogger()


def process_etiss_sim_log(etiss_log, csv, full_trace=0):
    """Process etiss simulation log.

    Extract instruction and affected register information from etiss simulation
    log and save to a list.
    """
    logging.info("Processing etiss log : {}".format(etiss_log))
    instr_cnt = 0
    etiss_instr = ""

    with open(etiss_log, "r") as f, open(csv, "w") as csv_fd:
        trace_csv = RiscvInstructionTraceCsv(csv_fd)
        trace_csv.start_new_trace()
        for line in f:
            # Extract instruction infromation
            m = INSTR_RE.search(line)
            c_m = C_INSTR_RE.search(line)
            if m:
                if illegal_instr_full(m.group('instr')):
                    continue
                logging.debug("-> mode: {}, pc:{}, bin:{}, instr:{}".format(
                  1, m.group('pc'), m.group('bin'),m.group('instr')))
                etiss_instr = assem_str(m)
                rv_instr_trace = RiscvInstructionTraceEntry()
                rv_instr_trace.instr = m.group('instr')
                rv_instr_trace.pc = m.group("pc")
                rv_instr_trace.instr_str = etiss_instr
                rv_instr_trace.binary = m.group("bin")
                rv_instr_trace.mode = '3'
                reg = "x" + m.group('rd_indx')
                rv_instr_trace.gpr.append(
                    gpr_to_abi(reg) + ":" + RD_VAL_RE.search(f.readline()).group('rd_val').zfill(8))
                trace_csv.write_trace_entry(rv_instr_trace)
            elif c_m:
                if illegal_instr(c_m.group('instr')):
                    logging.debug("-> mode: {}, pc:{}, bin:{}, instr:{}".format(
                      1, c_m.group('pc'), c_m.group('bin'),c_m.group('instr')))
                    rv_instr_trace = RiscvInstructionTraceEntry()
                    rv_instr_trace.instr = c_m.group('instr')
                    rv_instr_trace.pc = c_m.group("pc")
                    rv_instr_trace.instr_str = c_m.group('instr')
                    rv_instr_trace.binary = c_m.group("bin")
                    rv_instr_trace.mode = '1'
                    rd_line = RD_VAL_RE.search(f.readline())
                    #if rd_line:
                    reg = "x" + rd_line.group('rd_indx')
                    rv_instr_trace.gpr.append(
                        gpr_to_abi(reg) + ":" + rd_line.group('rd_val').zfill(8))
                    trace_csv.write_trace_entry(rv_instr_trace)
            elif line.find('ecall') != -1:
                break
            instr_cnt += 1
    logging.info("Processed instruction count : {}".format(instr_cnt))
    logging.info("CSV saved to : {}".format(csv))


def main():
    # Parse input arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", type=str, help="Input whisper simulation log")
    parser.add_argument("--csv", type=str, help="Output trace csv_buf file")
    parser.add_argument("-f", "--full_trace", dest="full_trace",
                        action="store_true",
                        help="Generate the full trace")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Verbose logging")
    parser.set_defaults(full_trace=False)
    parser.set_defaults(verbose=False)
    args = parser.parse_args()
    setup_logging(args.verbose)
    # Process whisper log
    process_etiss_sim_log(args.log, args.csv, args.full_trace)


if __name__ == "__main__":
    main()
