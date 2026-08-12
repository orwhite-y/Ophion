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
        for (int i = 0; i < count; i++) {
            StringBuilder name = new StringBuilder(256);
            GetDeviceDriverBaseName(bases[i], name, 256);
            Console.WriteLine("{0:X16} {1}", (ulong)bases[i], name.ToString());
        }
    }
}
