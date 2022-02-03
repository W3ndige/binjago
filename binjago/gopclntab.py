import binaryninja

from typing import Optional, List


class GopclntabStructure:
    __HEADER__ = b"\xFB\xFF\xFF\xFF\x00\x00"
    __HEADER16__ = b"\xFA\xFF\xFF\xFF\x00\x00"

    def __init__(self, header: Optional[bytes] = None, entries_counter: Optional[int] = None, entries: Optional[List] = None):
        if entries and entries_counter:
            if len(entries) != entries_counter:
                raise Exception()

        self.__address: Optional[int] = None
        self.__is16: Optional[bool] = False
        self.__header: Optional[bytes] = header
        self.__entries_counter: Optional[int] = entries_counter
        self.__entries: Optional[List] = entries

    @property
    def entries(self):
        return self.__entries

    @property
    def entries_counter(self):
        return self.__entries_counter

    def __update_entries(self, bv: binaryninja.binaryview.BinaryView) -> bool:
        if not self.__address or self.__is16:
            return False

        ptr_size = bv.arch.address_size
        size = bv.read_pointer(self.__address + 8)
        start_address = self.__address + 8 + ptr_size
        end_address = start_address + (size * ptr_size * 2)

        self.__entries_counter = 0
        while start_address < end_address:
            offset = bv.read_pointer(start_address + ptr_size)
            function_address = bv.read_pointer(self.__address + offset)
            function_name_address = bv.read_pointer(self.__address + offset + ptr_size, size=4) + self.__address
            function_name = bv.get_ascii_string_at(function_name_address)
            if not function_name:
                binaryninja.log_error(f"Couldn't recover function name from 0x{function_name_address}")
                continue

            function_name = function_name.value
            binaryninja.log_info(f"Found function {function_name} at 0x{hex(function_address)}")

            if self.__entries is None:
                self.__entries = []

            start_address += 2 * ptr_size
            self.__entries.append((function_address, function_name))
            self.__entries_counter += 1

    def __update_entries16(self, bv: binaryninja.binaryview.BinaryView) -> bool:
        if not self.__address or not self.__is16:
            return False

        ptr_size = bv.arch.address_size
        self.__entries_counter = bv.read_pointer(self.__address + 8)
        first_entry = bv.read_pointer(self.__address + ptr_size * 6 + 8) + self.__address
        function_names_start = self.__address + 8 + ptr_size * 7

        for i in range(self.__entries_counter):
            struct_ptr = bv.read_pointer(first_entry + i * ptr_size * 2 + 8) + first_entry
            function_address = bv.read_pointer(first_entry + i * ptr_size * 2)
            function_name = None

            try:
                function_name_address = bv.read_pointer(struct_ptr + 8, size=4) + function_names_start
                function_name = bv.get_ascii_string_at(function_name_address)
            except ValueError as e:
                binaryninja.log_error(str(e))
                continue

            if not function_name:
                binaryninja.log_error(f"Couldn't recover function name from 0x{function_name_address}")
                continue

            function_name = function_name.value
            binaryninja.log_info(f"Found function {function_name} at 0x{hex(function_address)}")
            if self.__entries is None:
                self.__entries = []

            self.__entries.append((function_address, function_name))

    def parse_fields(self, bv: binaryninja.binaryview.BinaryView, address: int):
        self.__address = address
        self.__is16 = False
        self.__header = bv.read(self.__address, 6)

        if self.__header == GopclntabStructure.__HEADER__:
            self.__update_entries(bv)

        elif self.__header == GopclntabStructure.__HEADER16__:
            self.__is16 = True
            self.__update_entries16(bv)

        else:
            binaryninja.log_error("Unsupported header")

    @staticmethod
    def find_structure(bv: binaryninja.binaryview.BinaryView) -> Optional[int]:
        base_address = None
        section = bv.get_section_by_name(".gopclntab")
        if section:
            base_address = section.start

        # Try to manually find the `.gopclntab` by looking for one of the available headers
        if not base_address:
            search_address = 0
            for header_constant in [GopclntabStructure.__HEADER__, GopclntabStructure.__HEADER16__]:
                candidate_address = bv.find_next_data(search_address, header_constant)

                # Validate potential candidate address
                if candidate_address and GopclntabStructure.validate_structure(bv, candidate_address):
                    base_address = candidate_address
                    break

                # In case the structure was invalid, resume searching from the previously found address
                elif candidate_address:
                    search_address = candidate_address + 1

        if base_address:
            binaryninja.log_info(f"Found .gopclntab structure at 0x{hex(base_address)}")

        return base_address

    @staticmethod
    def validate_structure(bv: binaryninja.binaryview.BinaryView, address: int):
        ptr_size = bv.arch.address_size
        header = bv.read(address, 6)
        if header == GopclntabStructure.__HEADER__:
            first_entry = bv.read_pointer(address + 8 + ptr_size)
            first_entry_offset = bv.read_pointer(address + 8 + ptr_size * 2)
            function_address = address + first_entry_offset
            function_loc = bv.read_pointer(function_address)
            if function_loc != first_entry:
                return False

        elif header == GopclntabStructure.__HEADER16__:
            offset = 8 + ptr_size * 6
            first_entry = bv.read_pointer(address + offset, ptr_size) + address
            function_loc = bv.read_pointer(first_entry, ptr_size)
            struct_ptr = bv.read_pointer(first_entry + 8, ptr_size) + first_entry
            first_entry = bv.read_pointer(struct_ptr, ptr_size)

            if function_loc != first_entry:
                return False
        else:
            binaryninja.log_info("Unknown .gopclntab header. Aborting")
            return False

        return True

    @staticmethod
    def from_bv(bv: binaryninja.binaryview.BinaryView, address: int, validated: bool = False):
        if not validated and not GopclntabStructure.validate_structure(bv, address):
            return None

        gopclntab = GopclntabStructure()
        gopclntab.parse_fields(bv, address)

        return gopclntab

    @staticmethod
    def rename_functions(bv: binaryninja.binaryview.BinaryView):
        base_address = GopclntabStructure.find_structure(bv)
        if not base_address:
            binaryninja.log_error("Couldn't find .gopclntab section")
            return

        gopclntab = GopclntabStructure.from_bv(bv, base_address)
        function_counter = 0
        for function_address, function_name in gopclntab.entries:
            function = bv.get_function_at(function_address)
            if not function:
                binaryninja.log_error(f"Couldn't find function at address 0x{hex(function_address)}")
                continue

            symbol = binaryninja.types.Symbol('FunctionSymbol', function_address, function_name, function_name)
            bv.define_user_symbol(symbol)
            function_counter += 1

        binaryninja.log_info(f"Successfully renamed {function_counter} functions.")






