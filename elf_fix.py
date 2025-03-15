# 脚本解读
# 1、parse_elf_segments计算出虚拟地址与文件地址有出入的内存段
# 2、fixer，存盘，即修复这些有出入的内存段,如何修复? 答: 按虚拟偏移把数据copy到对应的磁盘偏移中
# 3、至此，我们只需要把修复好的dump出来的文件全部patch到源文件上即可
# 4、或者我们也可以直接去彻底的修复dump出来的文件，首先我们copy并复写所有的 program_header_table，之后，我们copy复写所有的section_header_table与dynamic_symbol_table，最后我们修复字符串表，在源文件的section_header_table的某一条目中可以看到字符串表的偏移，直接copy过来并复写即可。
# 此处修复完了次文件

# 另外，需要修init、fini、got表
# 前两种好修，got表难修，每个got表应该指向对应的plt条目，dump下来后got表中每个条目都加了基地址，我们需要去除这个基地址，另外，got表是从第三项（0，1，2，3）开始算的，got表的地址与
# 长度都可以通过DYNAMIC得到，got表的长度也是从第三项开始算，不过got表的长度实际是代表了  ELF JMPREL Relocation Table 的长度，运算的时候需要转化一下
# x64只需要修GOT表就行了，其他重定位元素，由 RELA 额外提供的append自动修好了，参考: https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-54839/index.html
# x32考虑的要多一点，因为 x32没有RELA，只有REL，没有主动提供目的地址
# 在 x86 中仅使用 Elf32_Rel，而在 x86_64 上仅使用 Elf64_Rela。然而，这并不总是适用于每个体系结构，例如，SPARC 总是使用 Elfxx_Rela 的某个实例。参考: https://intezer.com/blog/malware-analysis/executable-and-linkable-format-101-part-3-relocations/
# x86的 R_386_32 模式太难计算了, 最终地址为 导入符号的绝对地址 + 文件上的对应值，参考: https://zhuanlan.zhihu.com/p/588913819，dumper需要提供dump时 导入符号的地址才行



# 不过貌似 R_386_32 上，不是+0，就是+8，是不是可以从中来操作呢，加下来详细解析   Elf32_Rel <16CD38h, 8D01h> ; R_386_32 _ZTVN10__cxxabiv120__si_class_type_infoE
# 其中的 0x8d代表了 ELF Symbol Table 中的第 0x8d项(0x00008DC)， 


# 为什么dump下来符号表可能会丢失了？看一下elf文件段的映射就会发现，其实有的elf文件符号表根本就没被映射到内存中，不过.so文件会被映射到内存中
import lief
from struct import pack,unpack
class DYNAMIC_mess:
    file_offset = -1
    virtual_offset = -1
    length = -1
    data_width = -1
    max_virtual_addr = -1
    def __init__(self,fo=-1,vo=-1,leng=-1,data_width=-1,max_virtual_addr=-1):
        self.file_offset = fo
        self.virtual_offset = vo
        self.length = leng
        self.data_width = data_width
        self.max_virtual_addr = max_virtual_addr
dyn_mess = DYNAMIC_mess()


seg_mess = []   # fa、va、size

def va2fa(va): 
    global seg_mess
    for i in range(len(seg_mess)-1):
        seg = seg_mess[i]
        seg_fa = seg[0]
        seg_va = seg[1]
        seg_leng = seg[2]
        if va >= seg_va and va <= seg_va + seg_leng:
            return seg_fa + (va-seg_va)
    
    return -1

def fa2va(fa):
    global seg_mess
    for i in range(len(seg_mess)-1):
        seg = seg_mess[i]
        seg_fa = seg[0]
        seg_va = seg[1]
        seg_leng = seg[2]
        if fa >= seg_fa and fa <= seg_fa + seg_leng:
            return seg_va + (fa-seg_fa)
    
    return -1

def parse_elf_segments(elf_path):
    global dyn_mess
    try:
        binary = lief.parse(elf_path)
        max_vir_addr = -1
        print(f"解析 ELF 文件: {elf_path}\n")
        print(f"{'Segment Type':<15} {'File Offset':<15} {'Virtual Addr':<18} {'Segment Size':<15}")
        print("-" * 70)
        fixed_addr_list = []
        for segment in binary.segments:
            seg_type = str(segment.type).split('.')[-1]  # 提取枚举类型的名字，如 PT_LOAD
            file_offset = segment.file_offset           # 在文件中的偏移
            vaddr = segment.virtual_address             # 在内存中的虚拟地址
            psize = segment.physical_size
            seg_mess.append((file_offset,vaddr,psize))
            if vaddr + psize > max_vir_addr :
                max_vir_addr = vaddr + psize


            if file_offset != vaddr:
                fixed_addr_list.append((seg_type,file_offset,vaddr,psize))
            print(f"{seg_type:<15} {hex(file_offset):<15} {hex(vaddr):<18} {hex(psize):<15}")
            if "DYNAMIC".lower() in seg_type.lower():
                dyn_mess.file_offset = file_offset
                dyn_mess.virtual_offset = vaddr
                dyn_mess.length = psize

        dyn_mess.max_virtual_addr = max_vir_addr 
        print("fixed_addr_list:")
        print(fixed_addr_list)
    except Exception as e:
        print(f"解析 ELF 文件时出错: {e}")
        assert 0
    return fixed_addr_list



def fixer_seg(fixed_file,fixed_seg_list):
    fp = open(fixed_file,"rb")
    content = fp.read()
    new_file = bytearray(content[:])
    for i in range(len(fixed_seg_list)):
        fix = fixed_seg_list[i]
        file_addr = fix[1]
        virtual_addr = fix[2]
        fixed_size = fix[3]
        virtual_mem = content[virtual_addr:virtual_addr+fixed_size]
        new_file[file_addr:file_addr+fixed_size] = virtual_mem[:]        
    fp.close()
    
    out_name = fixed_file + "_fixed"
    fp = open(out_name,"wb")
    fp.write(bytes(new_file))
    fp.close()
    return out_name

def fixer_DYNAMIC(fixed_file,dump_base):
    global dyn_mess
    if dyn_mess.file_offset == -1:
        print("error parse_elf_segments")
        assert 0
    fp = open(fixed_file,"rb")
    all_data = fp.read()
    begin = dyn_mess.file_offset
    width = dyn_mess.data_width
    length = dyn_mess.length
    
    all_fixer = []
    unpack_mode = ""
    if width == 8:
        unpack_mode = "<Q"
    elif width == 4:
        unpack_mode = "<I"
    else:
        print("error elf data width")
        assert 0



    # DYNAMIC about
    dyn_val = []
    for addr in range(begin,begin + length,width):
        elem = unpack(unpack_mode,all_data[addr:addr+width])[0]
        if elem >= dump_base:
            sub = elem - dump_base
            if sub >= 0 and sub < dyn_mess.max_virtual_addr:
                all_fixer.append((addr,sub,elem))
                dyn_val.append(sub)
                continue
        dyn_val.append(elem)
    

    # x64处理GOT about(R_X86_64_JUMP_SLOT) / x32处理 GOT about(R_386_JMP_SLOT)与 R_386_RELATIVE 
    got_va_addr = get_got_addr(dyn_val)
    got_fa_addr = va2fa(got_va_addr)
    print(f"got_va_addr => {hex(got_va_addr)}")
    print(f"got_fa_addr => {hex(got_fa_addr)}")
    got_size = get_got_size(dyn_val) 

    if width == 8:
        got_size = got_size // 3 
    elif width == 4:
        got_size = got_size // 2 
    print(f"got_table_size => {hex(got_size)}")

    global plt_addr


    if got_fa_addr == -1:
        print("no got table")
    else:
        cnt = 0
        for addr in range(got_fa_addr,got_fa_addr+got_size + width * 3,width):
            old_elem = unpack(unpack_mode,all_data[addr:addr+width])[0]
            if cnt <= 2:
                if cnt != 0:
                    all_fixer.append((addr,0,old_elem))
            else:
                all_fixer.append((addr,plt_addr,old_elem))
                plt_addr += 0x10
            cnt += 1

    if width == 4:
        # 处理 R_386_RELATIVE、R_ARM_RELATIVE
        DT_REL_va_addr = get_DT_REL(dyn_val)
        DT_REL_addr = va2fa(DT_REL_va_addr)
        DT_RELSZ = get_DT_RELSZ(dyn_val)
        if DT_REL_addr == -1 or DT_RELSZ == -1:
            assert 0
        tags = []
        for addr in range(DT_REL_addr,DT_REL_addr +DT_RELSZ,width):
            tags.append(unpack(unpack_mode,all_data[addr:addr+width])[0])
        
        for i in range(0,len(tags),2):
            r_offset  = tags[i]
            r_info = tags[i+1]
            fa_r_offset = va2fa(r_offset)
            r_val = unpack(unpack_mode,all_data[fa_r_offset:fa_r_offset + width])[0]
            # print(hex(r_val))
            if r_info == 8:             # 处理R_386_RELATIVE
                sub = r_val - dump_base
                if sub >= 0 and sub < dyn_mess.max_virtual_addr:
                    all_fixer.append((fa_r_offset,sub,r_val))
            elif r_info == 0x17:        # 处理R_ARM_RELATIVE，如果还有其他架构的32位，那么接着拓展就行了
                sub = r_val - dump_base
                if sub >= 0 and sub < dyn_mess.max_virtual_addr:
                    all_fixer.append((fa_r_offset,sub,r_val))
        
            
    # init_about
    init_array_addr = va2fa(get_init_array_addr(dyn_val))
    init_array_size = get_init_array_size(dyn_val)
    if init_array_addr == -1:
        print("no init_array table")
    else:
        for addr in range(init_array_addr,init_array_addr+init_array_size,width):
            elem = unpack(unpack_mode,all_data[addr:addr+width])[0]
            if elem >= dump_base:
                sub = elem - dump_base
                if sub >= 0 and sub < dyn_mess.max_virtual_addr:
                    all_fixer.append((addr,sub,elem))

    # fini_about
    fini_array_addr = va2fa(get_fini_array_addr(dyn_val))
    fini_array_size = get_fini_array_size(dyn_val)
    if fini_array_addr == -1:
        print("no fini_array table")
    else:
        for addr in range(fini_array_addr,fini_array_addr+fini_array_size,width):
            elem = unpack(unpack_mode,all_data[addr:addr+width])[0]
            if elem >= dump_base:
                sub = elem - dump_base
                if sub >= 0 and sub < dyn_mess.max_virtual_addr:
                    all_fixer.append((addr,sub,elem))

    # fixer
    new_data = bytearray(all_data[:])
    for i in range(len(all_fixer)):
        fix = all_fixer[i]
        addr = fix[0]
        val = fix[1]
        old_val = fix[2]
        new = pack(unpack_mode,val)
        new_data[addr:addr + width] = new
        print(f"[fix] {hex(fa2va(addr))},{hex(addr)}: {hex(old_val)} ==> {hex(val)}")
    fp.close()

    
    

    out_path = fixed_file + ".bin"
    fp = open(out_path,"wb")
    fp.write(bytes(new_data))
    fp.close()
    print("finish")
    print(f"out path => {out_path}")



# 通过解析DYNAMIC来修这俩
def get_got_addr(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 3:                   # GOT表
            got_addr = d_val
            return got_addr
    return -1

def get_got_size(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 2:                   # GOT表
            got_size = d_val
            return got_size 
    return -1

def get_init_array_addr(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 0x19:                   # DT_INIT_ARRAY
            got_addr = d_val
            return got_addr
    return -1

def get_init_array_size(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 0x1B:                   # DT_INIT_ARRAYSZ
            got_addr = d_val
            return got_addr
    return -1


def get_fini_array_addr(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 0x1A:                   # DT_FINI_ARRAY
            got_addr = d_val
            return got_addr
    return -1

def get_fini_array_size(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 0x1c:                   # DT_FINI_ARRAYSZ
            got_addr = d_val
            return got_addr
    return -1

def get_DT_REL(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 0x11:                   # DT_REL
            DT_REL_addr = d_val
            return DT_REL_addr
    return -1

def get_DT_RELSZ(dyn_val):
    for i in range(0,len(dyn_val)-2,2):
        dtag = dyn_val[i]
        d_val = dyn_val[i+1]
        if dtag == 0x12:                   # DT_RELSZ
            RELSZ = d_val
            return RELSZ
    return -1


data_width = 8
dump_base = 0x0000071EE52B000
file_name = "./so_64dump_so.so"
plt_addr = 0x0000000000C5A70            # push 0 , jmp xxx



dyn_mess.data_width = data_width
fixed_seg_list = parse_elf_segments(file_name)
out_name = fixer_seg(file_name,fixed_seg_list)
fixer_DYNAMIC(out_name,dump_base)



# 这样修对32位elf文件是有弱点的，其plt表全部从 jmp ptr变成了jmp [rbx+0x4*n]这种形式，丢失了符号，不过可以运行。因此我懒得进行处理
# 目前位置，除了搞定不了 32位的带导入符号的 elf文件、.so文件外，剩下的都能搞，我的下一步是参考 sofixer实现section的修复
# 另外。sofixer存在问题，没有实现 e_shoff的对齐，修复之后可以使用
