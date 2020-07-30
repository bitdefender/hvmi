#!/usr/bin/python
import json
import sys
from collections import OrderedDict

bindings = [
	{
		"IntroName": "Info",
		"KernelName": "",
		"Fields": [
		# 	{
		# 		"IntroName": "ThreadSize",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasModuleLayout",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasVdsoImageStruct",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasSmallSlack",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasKsymRelative",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasKsymAbsolutePercpu",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasKsymSize",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasAlternateSyscall",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasVmaAdjustExpand",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasVdsoFixed",
		# 		"KernelName": "",
		# 	},
		# 	{
		# 		"IntroName": "HasKsymReducedSize",
		# 		"KernelName": "",
		# 	},
		]
	},
	{
		"IntroName": "Module",
		"KernelName": "struct module",
		"Fields": [
			{
				"IntroName": "Sizeof",
				"KernelName": "sizeof",
			},
			{
				"IntroName": "ListOffset",
				"KernelName": "list",
			},
			{
				"IntroName": "NameOffset",
				"KernelName": "name",
			},
			{
				"IntroName": "SymbolsOffset",
				"KernelName": "syms",
			},
			{
				"IntroName": "NumberOfSymbolsOffset",
				"KernelName": "num_syms",
			},
			{
				"IntroName": "GplSymbolsOffset",
				"KernelName": "gpl_syms",
			},
			{
				"IntroName": "NumberOfGplSymbolsOffset",
				"KernelName": "num_gpl_syms",
			},
			{
				"IntroName": "InitOffset",
				"KernelName": "init",
			},
			{
				"IntroName": "ModuleInitOffset",
				"KernelName": "module_init",
			},
			{
				"IntroName": "ModuleCoreOffset",
				"KernelName": "module_core",
			},
			{
				"IntroName": "InitSizeOffset",
				"KernelName": "init_size",
			},
			{
				"IntroName": "CoreSizeOffset",
				"KernelName": "core_size",
			},
			{
				"IntroName": "InitTextSizeOffset",
				"KernelName": "init_text_size",
			},
			{
				"IntroName": "CoreTextSizeOffset",
				"KernelName": "core_text_size",
			},
			{
				"IntroName": "InitRoSizeOffset",
				"KernelName": "init_ro_size",
			},
			{
				"IntroName": "CoreRoSizeOffset",
				"KernelName": "core_ro_size",
			},
			{
				"IntroName": "CoreLayoutOffset",
				"KernelName": "core_layout",
			},
			{
				"IntroName": "InitLayoutOffset",
				"KernelName": "init_layout",
			},
			{
				"IntroName": "StateOffset",
				"KernelName": "state",
			},
		]
	},
	{
		"IntroName": "Binprm",
		"KernelName": "struct linux_binprm",
		"Fields": [
			{
				"IntroName": "Sizeof",
				"KernelName": "sizeof",
			},
			{
				"IntroName": "MmOffset",
				"KernelName": "mm",
			},
			{
				"IntroName": "FileOffset",
				"KernelName": "file",
			},
			{
				"IntroName": "CredOffset",
				"KernelName": "cred",
			},
			{
				"IntroName": "FilenameOffset",
				"KernelName": "filename",
			},
			{
				"IntroName": "InterpOffset",
				"KernelName": "interp",
			},
			{
				"IntroName": "Vma",
				"KernelName": "vma",
			},
			{
				"IntroName": "Argc",
				"KernelName": "argc",
			},
		]
	},
	{
		"IntroName": "Vma",
		"KernelName": "struct vm_area_struct",
		"Fields": [
			{
				"IntroName": "VmaStartOffset",
				"KernelName": "vm_start",
			},
			{
				"IntroName": "VmaEndOffset",
				"KernelName": "vm_end",
			},
			{
				"IntroName": "VmNextOffset",
				"KernelName": "vm_next",
			},
			{
				"IntroName": "VmPrevOffset",
				"KernelName": "vm_prev",
			},
			{
				"IntroName": "MmOffset",
				"KernelName": "vm_mm",
			},
			{
				"IntroName": "FlagsOffset",
				"KernelName": "vm_flags",
			},
			{
				"IntroName": "FileOffset",
				"KernelName": "vm_file",
			},
			{
				"IntroName": "RbNodeOffset",
				"KernelName": "vm_rb",
			},
		]
	},
	{
		"IntroName": "Dentry",
		"KernelName": "struct dentry",
		"Fields": [
			{
				"IntroName": "ParentOffset",
				"KernelName": "d_parent",
			},
			{
				"IntroName": "NameOffset",
				"KernelName": "d_name",
			},
			{
				"IntroName": "DinameOffset",
				"KernelName": "d_iname",
			},
			{
				"IntroName": "InodeOffset",
				"KernelName": "d_inode",
			},
		]
	},
	{
		"IntroName": "MmStruct",
		"KernelName": "struct mm_struct",
		"Fields": [
			{
				"IntroName": "PgdOffset",
				"KernelName": "pgd",
			},
			{
				"IntroName": "MmUsersOffset",
				"KernelName": "mm_users",
			},
			{
				"IntroName": "MmCountOffset",
				"KernelName": "mm_count",
			},
			{
				"IntroName": "MmListOffset",
				"KernelName": "mmlist",
			},
			{
				"IntroName": "StartCodeOffset",
				"KernelName": "start_code",
			},
			{
				"IntroName": "EndCodeOffset",
				"KernelName": "end_code",
			},
			{
				"IntroName": "StartDataOffset",
				"KernelName": "start_data",
			},
			{
				"IntroName": "EndDataOffset",
				"KernelName": "end_data",
			},
			{
				"IntroName": "FlagsOffset",
				"KernelName": "flags",
			},
			{
				"IntroName": "ExeFileOffset",
				"KernelName": "exe_file",
			},
			{
				"IntroName": "VmaOffset",
				"KernelName": "mmap",
			},
			{
				"IntroName": "StartStack",
				"KernelName": "start_stack",
			},
			{
				"IntroName": "RbNodeOffset",
				"KernelName": "mm_rb",
			},
		]
	},
	{
		"IntroName": "TaskStruct",
		"KernelName": "struct task_struct",
		"Fields": [
			{
				"IntroName": "StackOffset",
				"KernelName": "stack",
			},
			{
				"IntroName": "UsageOffset",
				"KernelName": "usage",
			},
			{
				"IntroName": "FlagsOffset",
				"KernelName": "flags",
			},
			{
				"IntroName": "TasksOffset",
				"KernelName": "tasks",
			},
			{
				"IntroName": "PidOffset",
				"KernelName": "pid",
			},
			{
				"IntroName": "TgidOffset",
				"KernelName": "tgid",
			},
			{
				"IntroName": "RealParentOffset",
				"KernelName": "real_parent",
			},
			{
				"IntroName": "ParentOffset",
				"KernelName": "parent",
			},
			{
				"IntroName": "MmOffset",
				"KernelName": "mm",
			},
			{
				"IntroName": "StartTimeOffset",
				"KernelName": "start_time",
			},
			{
				"IntroName": "CommOffset",
				"KernelName": "comm",
			},
			{
				"IntroName": "SignalOffset",
				"KernelName": "signal",
			},
			{
				"IntroName": "ExitCodeOffset",
				"KernelName": "exit_code",
			},
			{
				"IntroName": "ThreadNodeOffset",
				"KernelName": "thread_node",
			},
			{
				"IntroName": "ThreadGroupOffset",
				"KernelName": "thread_group",
			},
			{
				"IntroName": "CredOffset",
				"KernelName": "cred",
			},
			{
				"IntroName": "FsOffset",
				"KernelName": "fs",
			},
			{
				"IntroName": "FilesOffset",
				"KernelName": "files",
			},
			{
				"IntroName": "NsProxyOffset",
				"KernelName": "nsproxy",
			},
			{
				"IntroName": "GroupLeader",
				"KernelName": "group_leader",
			},
			{
				"IntroName": "ExitSignal",
				"KernelName": "exit_signal",
			},
			{
				"IntroName": "AltStackSp",
				"KernelName": "sas_ss_sp",
			},
		]
	},
	{
		"IntroName": "Fs",
		"KernelName": "struct fs_struct",
		"Fields": [
			{
				"IntroName": "Sizeof",
				"KernelName": "sizeof",
			},
			{
				"IntroName": "RootOffset",
				"KernelName": "root",
			},
			{
				"IntroName": "PwdOffset",
				"KernelName": "pwd",
			},
		]
	},
	{
		"IntroName": "FdTable",
		"KernelName": "struct fdtable",
		"Fields": [
			{
				"IntroName": "MaxFdsOffset",
				"KernelName": "max_fds",
			},
			{
				"IntroName": "FdOffset",
				"KernelName": "fd",
			},
		]
	},
	{
		"IntroName": "Files",
		"KernelName": "struct files_struct",
		"Fields": [
			{
				"IntroName": "Sizeof",
				"KernelName": "sizeof",
			},
			{
				"IntroName": "FdtOffset",
				"KernelName": "fdt",
			},
		]
	},
	{
		"IntroName": "Inode",
		"KernelName": "struct inode",
		"Fields": [
			{
				"IntroName": "Sizeof",
				"KernelName": "sizeof",
			},
			{
				"IntroName": "ImodeOffset",
				"KernelName": "i_mode",
			},
			{
				"IntroName": "UidOffset",
				"KernelName": "i_uid",
			},
			{
				"IntroName": "GidOffset",
				"KernelName": "i_gid",
			},
		]
	},
	{
		"IntroName": "Socket",
		"KernelName": "struct socket",
		"Fields": [
			{
				"IntroName": "StateOffset",
				"KernelName": "state",
			},
			{
				"IntroName": "TypeOffset",
				"KernelName": "type",
			},
			{
				"IntroName": "FlagsOffset",
				"KernelName": "flags",
			},
			{
				"IntroName": "SkOffset",
				"KernelName": "sk",
			},
		]
	},
	{
		"IntroName": "Sock",
		"KernelName": "struct sock_common",
		"Fields": [
			{
				"IntroName": "Sizeof",
				"KernelName": "sizeof",
			},
			{
				"IntroName": "NumOffset",
				"KernelName": "skc_num",
			},
			{
				"IntroName": "DportOffset",
				"KernelName": "skc_dport",
			},
			{
				"IntroName": "DaddrOffset",
				"KernelName": "skc_daddr",
			},
			{
				"IntroName": "RcvSaddrOffset",
				"KernelName": "skc_rcv_saddr",
			},
			{
				"IntroName": "FamilyOffset",
				"KernelName": "skc_family",
			},
			{
				"IntroName": "StateOffset",
				"KernelName": "skc_state",
			},
			{
				"IntroName": "ProtoOffset",
				"KernelName": "skc_prot",
			},
			{
				"IntroName": "V6DaddrOffset",
				"KernelName": "skc_v6_daddr",
			},
			{
				"IntroName": "V6RcvSaddrOffset",
				"KernelName": "skc_v6_rcv_saddr",
			},
		]
	},
	{
		"IntroName": "Cred",
		"KernelName": "struct cred",
		"Fields": [
			{
				"IntroName": "Sizeof",
				"KernelName": "sizeof",
			},
			{
				"IntroName": "UsageOffset",
				"KernelName": "usage",
			},
			{
				"IntroName": "RcuOffset",
				"KernelName": "rcu",
			},
		]
	},
	{
		"IntroName": "NsProxy",
		"KernelName": "struct nsproxy",
		"Fields": [
			# {
			# 	"IntroName": "CountOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "UtsOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "IpcOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "MntOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "PidOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "NetOffset",
			# 	"KernelName": "",
			# },
		]
	},
	{
		"IntroName": "Ungrouped",
		"KernelName": "",
		"Fields": [
			# {
			# 	"IntroName": "FileDentryOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "ProtoNameOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "SignalListHeadOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "SocketAllocVfsInodeOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "Running",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "FilePathOffset",
			# 	"KernelName": "",
			# },
			# {
			# 	"IntroName": "SignalNrThreadsOffset",
			# 	"KernelName": "",
			# },
		]
	},
]

def create_bindings(input_dict):
    result = []
    for struct in bindings:
        st = struct["KernelName"]
        f = []
        for field in struct["Fields"]:
            try:
                f.append((field["IntroName"], input_dict[struct["KernelName"]][field["KernelName"]]))
            except KeyError:
                pass
        result.append((struct["IntroName"], f))
    return result

def generate_hooks(functions):
    result = "hooks:\n"
    for func in functions:
        result += "\t- !intro_update_lix_hook\n"
        result += "\t\tname: " + func + "\n"
        result += "\t\thandler: 0\n\t\tskip_on_boot: 0\n\n"
    return result



def generate_yaml_string(content, version):
    result = "#!intro_update_lix_supported_os\n"
    result += "version: " + version + "\n\n"

    result += "fields: !opaque_structures\n\ttype: !lix_fields\n\tos_structs:\n"

    for struct in content:
        result += "\t\t" + struct[0] + ": !opaque_fields\n"
        for field in struct[1]:
            result += "\t\t\t" + field[0] + ": 0x%04x\n" % (field[1])

    return result

def main():
    if len(sys.argv) < 3:
        print("Use %s <input file> <output file>", sys.argv[1])
        return

    inp = sys.argv[1]
    outp = sys.argv[2]

    with open(inp, "r") as f:
        input_js = json.load(f)

    bindings = create_bindings(input_js)
    result = generate_yaml_string(bindings, input_js["_KERNEL_VERSION_"])
    result += generate_hooks(input_js["_FUNCTIONS_"])

    print("done")

    with open(outp, "w") as f:
        f.write(result)

main()
