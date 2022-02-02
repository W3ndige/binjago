from .binjago.gopclntab import GopclntabStructure

from binaryninja import PluginCommand

PluginCommand.register(
    "binjago",
    "Automatically rename go functions based on symbol table",
    GopclntabStructure.rename_functions
)
