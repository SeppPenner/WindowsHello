using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WindowsHello;

namespace WinHelloTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var handle = new IntPtr();
            string message = "Windows Hello Test";
            var data = new byte[] { 0x32, 0x32 };
            Console.WriteLine(BitConverter.ToString(data));
            IAuthProvider provider = WinHelloProvider.CreateInstance(message, handle);
            Console.WriteLine("Instance Created.");
            var encryptedData = provider.Encrypt(data);
            Console.WriteLine("Encrypted data:");
            Console.WriteLine(BitConverter.ToString(encryptedData));
            var decryptedData = provider.PromptToDecrypt(encryptedData);
            Console.WriteLine("Decrypted data:");
            Console.WriteLine(BitConverter.ToString(decryptedData));
            WinHelloProvider.DeletePersistentKey();
            Console.ReadKey();
        }
    }
}
