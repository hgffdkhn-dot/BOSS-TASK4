#!/usr/bin/env python3
"""造一个合成的属性区（prop_area），供 resetprop 在无真机的环境下验证。

布局严格对齐 bionic 的 prop_area / prop_trie_node / prop_info：
  prop_area      : bytes_used_ serial_ magic_ version_ reserved_[28] data_[]
                 = 4 + 4 + 4 + 4 + 112 = 128 字节
  data_ 起点     : 文件偏移 128
  prop_trie_node : namelen prop left right children name[]   (20 + namelen + 1)
  prop_info      : serial value[92] name[]                   (96 + namelen + 1)
  对象偏移       : 相对 data_ 起点（即文件偏移 128 + off）
  serial         : (value_len << 24) | (serial & 0xffffff)

用法：python3 tools/mkprop.py <目录> name=value [name=value ...]
"""
import os
import struct
import sys

PA_SIZE = 128 * 1024
HEADER = 128
MAGIC = 0x504F5250
VERSION = 0xFC6ED0AB
PROP_VALUE_MAX = 92


class Area:
    def __init__(self):
        self.buf = bytearray(PA_SIZE)
        # bytes_used_ 初值 = sizeof(prop_trie_node) + align(PROP_VALUE_MAX, 4)
        self.used = 20 + PROP_VALUE_MAX          # dirty backup area 也占着

    def alloc(self, size):
        aligned = (size + 3) & ~3
        off = self.used
        if off + aligned > PA_SIZE - HEADER:
            raise RuntimeError("合成属性区溢出（测试属性太多）")
        self.used += aligned
        return off

    def new_node(self, name):
        """返回节点在 data_ 内的偏移"""
        nb = name.encode()
        off = self.alloc(20 + len(nb) + 1)
        base = HEADER + off
        struct.pack_into('<I', self.buf, base, len(nb))
        self.buf[base + 20:base + 20 + len(nb)] = nb
        return off

    def new_info(self, name, value):
        nb = name.encode()
        off = self.alloc(96 + len(nb) + 1)
        base = HEADER + off
        # serial = (value_len << 24) | (serial & 0xffffff)；bit0 是 dirty 位，
        # 初始值必须让它是偶数，否则读侧会跑去 dirty backup area 取空值。
        serial = (len(value.encode()) << 24) | 2
        struct.pack_into('<I', self.buf, base, serial)
        self.buf[base + 4:base + 4 + len(value.encode())] = value.encode()
        self.buf[base + 96:base + 96 + len(nb)] = nb
        return off

    # 节点字段读写（字段在节点内偏移：namelen0 prop4 left8 right12 children16）
    def get(self, node_off, field):
        base = HEADER + node_off + field
        return struct.unpack_from('<I', self.buf, base)[0]

    def set(self, node_off, field, val):
        base = HEADER + node_off + field
        struct.pack_into('<I', self.buf, base, val)

    def add(self, name, value):
        root = 0                      # root_node() = data_ + 0
        cur = root
        remaining = name
        while True:
            sep = remaining.find('.')
            want_sub = sep >= 0
            seg = remaining[:sep] if want_sub else remaining
            if not seg:
                raise ValueError("空的属性段: " + name)

            children = self.get(cur, 16)
            if children == 0:
                children = self.new_node(seg)
                self.set(cur, 16, children)
                cur = children
            else:
                # 在兄弟二叉搜索树里找（比较规则：先比长度，再比内容）
                p = children
                while True:
                    plen = self.get(p, 0)
                    pname = self.buf[HEADER + p + 20:HEADER + p + 20 + plen].decode()
                    cmpv = (len(seg) > plen) - (len(seg) < plen)
                    if cmpv == 0:
                        cmpv = (seg > pname) - (seg < pname)
                    if cmpv == 0:
                        cur = p
                        break
                    slot = 8 if cmpv < 0 else 12    # left / right
                    nxt = self.get(p, slot)
                    if nxt == 0:
                        nxt = self.new_node(seg)
                        self.set(p, slot, nxt)
                        cur = nxt
                        break
                    p = nxt

            if not want_sub:
                break
            remaining = remaining[sep + 1:]

        info = self.new_info(name, value)
        self.set(cur, 4, info)

    def write(self, path):
        struct.pack_into('<IIII', self.buf, 0, self.used, 0, MAGIC, VERSION)
        with open(path, 'wb') as f:
            f.write(self.buf)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)

    # properties_serial：全局 serial 所在的小块，resetprop 改完属性会自增它
    serial = Area()
    serial.write(os.path.join(outdir, 'properties_serial'))

    # 按属性名前缀分组到不同"区域文件"（真实设备上按 property_contexts 划分）
    groups = {}
    for item in sys.argv[2:]:
        if '=' not in item:
            continue
        k, v = item.split('=', 1)
        prefix = k.split('.')[0]
        groups.setdefault(prefix, []).append((k, v))

    for prefix, props in sorted(groups.items()):
        area = Area()
        for k, v in props:
            area.add(k, v)
        # 文件名即 context，与 8.0+ 的多区域一致
        fname = 'u:object_r:%s_prop:s0' % prefix
        path = os.path.join(outdir, fname)
        area.write(path)
        print("已生成 %s  (%d 条属性)" % (path, len(props)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
