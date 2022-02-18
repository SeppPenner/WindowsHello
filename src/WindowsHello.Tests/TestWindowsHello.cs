// --------------------------------------------------------------------------------------------------------------------
// <copyright file="TestWindowsHello.cs" company="Hämmer Electronics">
//   Copyright (c) 2020 All rights reserved.
// </copyright>
// <summary>
//   This class is used to test the Microsoft Windows Hello
//   (https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) functionality.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Tests;

/// <summary>
///     This class is used to test the Microsoft Windows Hello
///     (https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) functionality.
/// </summary>
[TestClass]
public class TestWindowsHello
{
    /// <summary>
    ///     Tests the Microsoft Windows Hello functionality.
    /// </summary>
    [TestMethod]
    public void WindowsHelloTest()
    {
        var handle = new IntPtr();
        const string Message = "Windows Hello Test";
        var data = new byte[] { 0x32, 0x32 };
        Console.WriteLine(BitConverter.ToString(data));
        var provider = WinHelloProvider.CreateInstance(Message, handle);
        Console.WriteLine("Instance created.");
        var encryptedData = provider.Encrypt(data);
        Console.WriteLine("Encrypted data:");
        Console.WriteLine(BitConverter.ToString(encryptedData));
        var decryptedData = provider.PromptToDecrypt(encryptedData);
        Console.WriteLine("Decrypted data:");
        Console.WriteLine(BitConverter.ToString(decryptedData));
        CollectionAssert.AreEqual(data, decryptedData);
    }

    /// <summary>
    ///     Tests the Microsoft Windows Hello functionality.
    /// </summary>
    [TestMethod]
    public void WindowsHelloTest2()
    {
        var handle = new IntPtr();
        const string Message = "Windows Hello Test2";
        var data = new byte[] { 0x32, 0x32 };
        Console.WriteLine(BitConverter.ToString(data));
        var provider = WinHelloProvider.CreateInstance(Message, handle);
        Console.WriteLine("Instance created.");
        provider.SetPersistentKeyName("Test");
        Console.WriteLine("PersistentKeyName set to \"Test\".");
        var encryptedData = provider.Encrypt(data);
        Console.WriteLine("Encrypted data:");
        Console.WriteLine(BitConverter.ToString(encryptedData));
        var decryptedData = provider.PromptToDecrypt(encryptedData);
        Console.WriteLine("Decrypted data:");
        Console.WriteLine(BitConverter.ToString(decryptedData));
        CollectionAssert.AreEqual(data, decryptedData);
    }
}
