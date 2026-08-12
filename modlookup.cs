using System;
using System.Runtime.InteropServices;
using System.Text;
class M {
    [DllImport("psapi.dll")]
    static extern int EnumDeviceDrivers(IntPtr[] lpImageBase, int cb, out int lpcbNeeded);
    [DllImport("psapi.dll")]
    static extern int GetDeviceDriverBaseName(IntPtr ImageBase, StringBuilder lpBaseName, int nSize);
    static void Main() {
        int needed;
        EnumDeviceDrivers(null, 0, out needed);
        int count = needed / IntPtr.Size;
        IntPtr[] bases = new IntPtr[count];
        EnumDeviceDrivers(bases, needed, out needed);
        ulong[] targets = { 0xfffff8054d7002e0, 0xfffff8054d7033a0, 0xfffff8054d6ffbc4 };
        for (int i = 0; i < count; i++) {
            ulong baseVal = (ulong)bases[i];
            StringBuilder name = new StringBuilder(256);
            GetDeviceDriverBaseName(bases[i], name, 256);
            // assume module size up to 16MB
            foreach (ulong t in targets) {
                if (t >= baseVal && t < baseVal + 0x1000000) {
                    Console.WriteLine("HIT: 0x" + t.ToString("X") + " in " + name.ToString() + " base=0x" + baseVal.ToString("X"));
                }
            }
        }
        Console.WriteLine("Done");
    }
}