import idaapi
import idautils
import idc
import ida_search

'''
   Hi user, this is a funny ida function finder
   i spent a good hour on the orginal code but it works for the most part
   ProcessEvent worked, doesnt now.
   Everything else has been for a little bit now

   - made by github.com/vmpprotect
'''

class FindFunctionsPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "vmp func finder"
    help = "This plugin finds UE Functions with a specific args"
    wanted_name = "FindFunctions"
    wanted_hotkey = "Alt-F"

    def init(self):
        print("[Debug] Plugin initialized")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg_clear()
        print("[vmp-fn] Plugin run")
        self.find_functions()

    def term(self):
        print("[vmp-ue] Plugin terminated")

    def find_functions(self):
        print("[vmp-ue] Starting to find functions")
        
        print("[vmp-ue] Analyzing all functions...")
        for seg in idautils.Segments():
            start = idc.get_segm_start(seg)
            end = idc.get_segm_end(seg)
            idc.plan_and_wait(start, end)
        
        idaapi.auto_wait()
        
        for func in idautils.Functions():
            func_name = idc.get_func_name(func)
            func_type = idc.get_type(func)
            
            # StaticFindObject pattern
            if func_type and "(__int64, __int64, __int64, char)" in func_type:
                image_base = idaapi.get_imagebase()
                offset = func - image_base
                print(f"[+] Found StaticFindObject : {func_name} at {hex(func)}")
                print(f"[+] StaticFindObject Offset: {hex(offset)}")
            
            # StaticLoadObject pattern (existing)
            if func_type and "(__int64 , __int64 , __int64 , __int64)" in func_type:
                image_base = idaapi.get_imagebase()
                offset = func - image_base
                print(f"[+] Found StaticLoadObject : {func_name} at {hex(func)}")
                print(f"[+] StaticLoadObject Offset: {hex(offset)}")

            # StaticLoadObject pattern (new signature)
            if func_type and "(__int64, __int64)" in func_type:
                for head in idautils.FuncItems(func):
                    if idc.print_insn_mnem(head) == "call":
                        called_operand = idc.get_operand_value(head, 0)
                        
                        disasm_line = idc.generate_disasm_line(head, 0)
                        if disasm_line and "dword" in disasm_line:
                            arg_count = 0
                            current = head
                            while current != idc.BADADDR:
                                if idc.print_insn_mnem(current) in ["push", "mov"]:
                                    arg_count += 1
                                current = idc.prev_head(current)
                                if arg_count >= 6:
                                    break
                            
                            if arg_count == 6:
                                dword_address = idc.get_operand_value(head, 0)
                                image_base = idaapi.get_imagebase()
                                offset = func - image_base
                                
                                print(f"[+] Found function containing STLO: {func_name} at {hex(func)}")
                                print(f"[+] StaticLoadObject Address: {hex(dword_address)}")
                                break

            # FMemory::Malloc pattern
            if func_type and "(unsigned __int64, unsigned int)" in func_type:
                image_base = idaapi.get_imagebase()
                offset = func - image_base
                print(f"[+] Found FMemory::Malloc : {func_name} at {hex(func)}")
                print(f"[+] FMemory::Malloc Offset: {hex(offset)}")
            
            # UObject::ProcessEvent pattern
            if func_type and "(unsigned __int64, __int64, __int64)" in func_type:
                image_base = idaapi.get_imagebase()
                offset = func - image_base
                print(f"[+] Found UObject::ProcessEvent : {func_name} at {hex(func)}")
                print(f"[+] UObject::ProcessEvent Offset: {hex(offset)}")

            if func_type and "(_DWORD *a1, __int64 a2, __int64 a3)" in func_type:
                image_base = idaapi.get_imagebase()
                offset = func - image_base
                print(f"[+] Found UObject::ProcessEvent : {func_name} at {hex(func)}")
                print(f"[+] UObject::ProcessEvent Offset: {hex(offset)}")

def PLUGIN_ENTRY():
    return FindFunctionsPlugin()
