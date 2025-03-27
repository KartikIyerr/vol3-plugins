import logging
from typing import List, Generator, Optional

from volatility3.framework import interfaces, renderers, constants, logging as vollog
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import windows
from volatility3.plugins.windows import pslist

class APCWatch(interfaces.plugins.PluginInterface):
    """Detects Asynchronous Procedure Calls (APC) for each process"""

    _required_framework_version = (2, 4, 0)
    _version = (3, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True
            )
        ]

    def run(self):
        """
        Generate precise APC information based on _KAPC and _KAPC_STATE structures
        """
        kernel = self.context.modules[self.config['kernel']]
        layer_name = kernel.layer_name
        symbol_table_name = kernel.symbol_table_name

        # Create PID filter
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        # Columns for output (added Process Name column)
        columns = [
            ("Process Name", str),  # Added column for process name
            ("PID", int),
            ("TID", int),
            ("KernelRoutine", format_hints.Hex),
            ("NormalRoutine", format_hints.Hex),
            ("APCMode", str),
            ("Inserted", bool),
            ("KernelAPC", bool),
            ("SpecialAPC", bool),
            ("KernelAPCPending", bool),
            ("UserAPCPending", bool)
        ]

        return renderers.TreeGrid(
            columns, 
            self._apc_generator(
                context=self.context,
                layer_name=layer_name,
                symbol_table_name=symbol_table_name,
                filter_func=filter_func
            )
        )

    def _apc_generator(
        self, 
        context: interfaces.context.ContextInterface, 
        layer_name: str, 
        symbol_table_name: str, 
        filter_func
    ) -> Generator[tuple, None, None]:
        """
        Generate detailed APC entries from thread structures
        """
        for proc in pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table_name,
            filter_func=filter_func
        ):
            for thread in proc.ThreadListHead.to_list(
                f"{symbol_table_name}{constants.BANG}_ETHREAD", 
                "ThreadListEntry"
            ):
                try:
                    # Access KAPC_STATE directly
                    apc_state = thread.Tcb.ApcState

                    for list_index, apc_list in enumerate(apc_state.ApcListHead):
                        for apc in apc_list.to_list(
                            f"{symbol_table_name}{constants.BANG}_KAPC", 
                            "ApcListEntry"
                        ):
                            yield (0, (
                                proc.ImageFileName.cast("string", max_length=256, errors="replace"),  # Process Name
                                int(thread.Cid.UniqueProcess),  # PID
                                int(thread.Cid.UniqueThread),   # TID
                                format_hints.Hex(apc.KernelRoutine.vol.offset),  # Kernel Routine
                                format_hints.Hex(apc.NormalRoutine.vol.offset),  # Normal Routine
                                "Kernel" if apc.ApcMode == 0 else "User",  # APC Mode
                                bool(apc.Inserted),  # Inserted flag
                                bool(apc_state.InProgressFlags & 0x1),  # Kernel APC In Progress
                                bool(apc_state.InProgressFlags & 0x2),  # Special APC In Progress
                                bool(apc_state.KernelApcPending),  # Kernel APC Pending
                                bool(apc_state.UserApcPending)  # User APC Pending
                            ))
                
                except Exception as e:
                    vollog.debug(f"Error scanning thread {thread.Cid.UniqueThread}: {e}")