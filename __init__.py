from .binjago.gopclntab import rename_functions

from binaryninja import PluginCommand

PluginCommand.register(
    "binjago",
    "Automatically rename go functions based on symbol table",
    rename_functions
)
