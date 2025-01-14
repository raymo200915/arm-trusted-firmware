#
# Copyright (c) 2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#


class TfaPrettyPrinter:
    """A class for printing the memory layout of ELF files.

    This class provides interfaces for printing various memory layout views of
    ELF files in a TF-A build. It can be used to understand how the memory is
    structured and consumed.
    """

    def __init__(self, columns: int = None, as_decimal: bool = False):
        self.term_size = columns if columns and columns > 120 else 120
        self._symbol_map = None
        self.as_decimal = as_decimal

    def format_args(self, *args, width=10, fmt=None):
        if not fmt and type(args[0]) is int:
            fmt = f">{width}x" if not self.as_decimal else f">{width}"
        return [f"{arg:{fmt}}" if fmt else arg for arg in args]

    @staticmethod
    def map_elf_symbol(
        leading: str,
        section_name: str,
        rel_pos: int,
        columns: int,
        width: int = None,
        is_edge: bool = False,
    ):
        empty_col = "{:{}{}}"

        # Some symbols are longer than the column width, truncate them until
        # we find a more elegant way to display them!
        len_over = len(section_name) - width
        if len_over > 0:
            section_name = section_name[len_over:-len_over]

        sec_row = f"+{section_name:-^{width-1}}+"
        sep, fill = ("+", "-") if is_edge else ("|", "")

        sec_row_l = empty_col.format(sep, fill + "<", width) * rel_pos
        sec_row_r = empty_col.format(sep, fill + ">", width) * (
            columns - rel_pos - 1
        )

        return leading + sec_row_l + sec_row + sec_row_r

    def print_symbol_table(
        self,
        symbols: list,
        modules: list,
        start: int = 11,
    ):
        assert len(symbols), "Empty symbol list!"
        modules = sorted(modules)
        col_width = int((self.term_size - start) / len(modules))

        num_fmt = "0=#010x" if not self.as_decimal else ">10"

        _symbol_map = [
            " " * start
            + "".join(self.format_args(*modules, fmt=f"^{col_width}"))
        ]
        last_addr = None

        for i, (name, addr, mod) in enumerate(symbols):
            # Do not print out an address twice if two symbols overlap,
            # for example, at the end of one region and start of another.
            leading = (
                f"{addr:{num_fmt}}" + " " if addr != last_addr else " " * start
            )

            _symbol_map.append(
                self.map_elf_symbol(
                    leading,
                    name,
                    modules.index(mod),
                    len(modules),
                    width=col_width,
                    is_edge=(not i or i == len(symbols) - 1),
                )
            )

            last_addr = addr

        self._symbol_map = ["Memory Layout:"]
        self._symbol_map += list(reversed(_symbol_map))
        print("\n".join(self._symbol_map))
