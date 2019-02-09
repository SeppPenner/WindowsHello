namespace WindowsHello.Tests
{
    using WindowsHello;

    using System;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// This class is used to test the Microsoft Windows Hello (https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) functionality. 
    /// </summary>
    [TestClass]
    public class TestWindowsHello
    {
        /// <summary>
        /// Tests the Microsoft Windows Hello functionality. 
        /// </summary>
        [TestMethod]
        public void WindowsHelloTest()
        {
            var handle = new IntPtr();
            var data = new byte[] { 0x32, 0x32 };
            IAuthProvider provider = new WinHelloProvider("Hello", handle);
            var encryptedData = provider.Encrypt(data);
            var decryptedData = provider.PromptToDecrypt(encryptedData);
            CollectionAssert.AreEqual(data, decryptedData);
        }
    }
}
