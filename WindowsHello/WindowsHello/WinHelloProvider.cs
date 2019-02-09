using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace WindowsHello
{
    /// <inheritdoc cref="IAuthProvider" />
    /// <summary>
    ///     This class provides access to the Microsoft Windows Hello (https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) functionality. 
    /// </summary>
    /// <seealso cref="IAuthProvider" />
    public class WinHelloProvider : IAuthProvider
    {
        /// <summary>
        ///     The Microsoft NGC key storage provider.
        /// </summary>
        private const string MsNgcKeyStorageProvider = "Microsoft Passport Key Storage Provider";

        /// <summary>
        ///     The ncrypt pad PKC s1 flag.
        /// </summary>
        [SuppressMessage(
            "StyleCop.CSharp.DocumentationRules",
            "SA1650:ElementDocumentationMustBeSpelledCorrectly",
            Justification = "Reviewed. Suppression is OK here.")]
        private const int NcryptPadPkcs1Flag = 0x00000002;

        /// <summary>
        ///     The ncrypt pin cache is gesture required property.
        /// </summary>
        [SuppressMessage(
            "StyleCop.CSharp.DocumentationRules",
            "SA1650:ElementDocumentationMustBeSpelledCorrectly",
            Justification = "Reviewed. Suppression is OK here.")]
        private const string NcryptPinCacheIsGestureRequiredProperty = "PinCacheIsGestureRequired";

        /// <summary>
        ///     The ncrypt use context property.
        /// </summary>
        [SuppressMessage(
            "StyleCop.CSharp.DocumentationRules",
            "SA1650:ElementDocumentationMustBeSpelledCorrectly",
            Justification = "Reviewed. Suppression is OK here.")]
        private const string NcryptUseContextProperty = "Use Context";

        /// <summary>
        ///     The ncrypt window handle property.
        /// </summary>
        [SuppressMessage(
            "StyleCop.CSharp.DocumentationRules",
            "SA1650:ElementDocumentationMustBeSpelledCorrectly",
            Justification = "Reviewed. Suppression is OK here.")]
        private const string NcryptWindowHandleProperty = "HWND Handle";

        /// <summary>
        ///     The nte user cancelled property.
        /// </summary>
        [SuppressMessage(
            "StyleCop.CSharp.DocumentationRules",
            "SA1650:ElementDocumentationMustBeSpelledCorrectly",
            Justification = "Reviewed. Suppression is OK here.")]
        private const int NteUserCancelledProperty = unchecked((int)0x80090036);

        /// <summary>
        ///     The current passport key name.
        /// </summary>
        private static readonly Lazy<string> CurrentPassportKeyName = new Lazy<string>(RetrievePassportKeyName);

        /// <summary>
        ///     Initializes a new instance of the <see cref="WinHelloProvider" /> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="parentHandle">The parent handle.</param>
        public WinHelloProvider(string message, IntPtr parentHandle)
        {
            this.Message = message;
            this.ParentHandle = parentHandle;
        }

        /// <summary>
        ///     Gets or sets the message text shown in the authenticator Gui.
        /// </summary>
        /// <value>
        ///     The message text shown in the authenticator Gui.
        /// </value>
        [SuppressMessage(
            "StyleCop.CSharp.DocumentationRules",
            "SA1650:ElementDocumentationMustBeSpelledCorrectly",
            Justification = "Reviewed. Suppression is OK here.")]
        public string Message { get; set; }

        /// <summary>
        ///     Gets or sets the parent handle.
        /// </summary>
        /// <value>
        ///     The parent handle.
        /// </value>
        public IntPtr ParentHandle { get; set; }

        /// <summary>
        ///     Sets the CHK result.
        /// </summary>
        /// <value>
        ///     The CHK result.
        /// </value>
        /// <exception cref="UnauthorizedAccessException">Operation canceled</exception>
        /// <exception cref="ExternalException">External error occurred</exception>
        private static int ChkResult
        {
            set
            {
                if (value >= 0)
                {
                    return;
                }

                // NTE_BAD_FLAGS
                // NTE_BAD_KEYSET
                // NTE_BAD_KEY_STATE
                // NTE_BUFFER_TOO_SMALL
                // NTE_INVALID_HANDLE
                // NTE_INVALID_PARAMETER
                // NTE_PERM
                // NTE_NO_MEMORY
                // NTE_NOT_SUPPORTED
                // NTE_USER_CANCELLED
                switch (value)
                {
                    case NteUserCancelledProperty:
                        throw new UnauthorizedAccessException("Operation canceled");
                    default:
                        throw new ExternalException("External error occurred", value);
                }
            }
        }

        /// <summary>
        ///     Determines whether this instance is available.
        /// </summary>
        /// <returns>
        ///     <c>true</c> if this instance is available; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsAvailable()
        {
            return !string.IsNullOrEmpty(CurrentPassportKeyName.Value);
        }

        /// <inheritdoc cref="IAuthProvider" />
        /// <summary>
        ///     Encrypts the specified data.
        /// </summary>
        /// <param name="data">The decrypted data.</param>
        /// <returns>
        ///     The encrypted data as <see cref="T:byte[]" />.
        /// </returns>
        /// <exception cref="NotSupportedException">Windows Hello is not available</exception>
        public byte[] Encrypt(byte[] data)
        {
            if (!IsAvailable())
            {
                throw new NotSupportedException("Windows Hello is not available");
            }

            byte[] result;
            ChkResult = NCryptOpenStorageProvider(out var ngcProviderHandle, MsNgcKeyStorageProvider, 0);
            using (ngcProviderHandle)
            {
                ChkResult = NCryptOpenKey(
                    ngcProviderHandle,
                    out var ngcKeyHandle,
                    CurrentPassportKeyName.Value,
                    0,
                    CngKeyOpenOptions.Silent);
                using (ngcKeyHandle)
                {
                    ChkResult = NCryptEncrypt(
                        ngcKeyHandle,
                        data,
                        data.Length,
                        IntPtr.Zero,
                        null,
                        0,
                        out var pcbResult,
                        NcryptPadPkcs1Flag);

                    result = new byte[pcbResult];
                    ChkResult = NCryptEncrypt(
                        ngcKeyHandle,
                        data,
                        data.Length,
                        IntPtr.Zero,
                        result,
                        result.Length,
                        out pcbResult,
                        NcryptPadPkcs1Flag);
                }
            }

            return result;
        }

        /// <inheritdoc cref="IAuthProvider" />
        /// <summary>
        ///     Prompts to decrypt the data.
        /// </summary>
        /// <param name="data">The encrypted data.</param>
        /// <returns>
        ///     The decrypted data as <see cref="T:byte[]" />.
        /// </returns>
        /// <exception cref="T:System.NotSupportedException">Windows Hello is not available</exception>
        public byte[] PromptToDecrypt(byte[] data)
        {
            if (!IsAvailable())
            {
                throw new NotSupportedException("Windows Hello is not available");
            }

            byte[] result;
            ChkResult = NCryptOpenStorageProvider(out var ngcProviderHandle, MsNgcKeyStorageProvider, 0);
            using (ngcProviderHandle)
            {
                ChkResult = NCryptOpenKey(
                    ngcProviderHandle,
                    out var ngcKeyHandle,
                    CurrentPassportKeyName.Value,
                    0,
                    CngKeyOpenOptions.None);
                using (ngcKeyHandle)
                {
                    if (this.ParentHandle != IntPtr.Zero)
                    {
                        var handle = BitConverter.GetBytes(
                            IntPtr.Size == 8 ? this.ParentHandle.ToInt64() : this.ParentHandle.ToInt32());
                        ChkResult = NCryptSetProperty(
                            ngcKeyHandle,
                            NcryptWindowHandleProperty,
                            handle,
                            handle.Length,
                            CngPropertyOptions.None);
                    }

                    if (!string.IsNullOrEmpty(this.Message))
                    {
                        ChkResult = NCryptSetProperty(
                            ngcKeyHandle,
                            NcryptUseContextProperty,
                            this.Message,
                            (this.Message.Length + 1) * 2,
                            CngPropertyOptions.None);
                    }

                    var pinRequired = BitConverter.GetBytes(1);
                    ChkResult = NCryptSetProperty(
                        ngcKeyHandle,
                        NcryptPinCacheIsGestureRequiredProperty,
                        pinRequired,
                        pinRequired.Length,
                        CngPropertyOptions.None);

                    result = new byte[data.Length * 2];
                    ChkResult = NCryptDecrypt(
                        ngcKeyHandle,
                        data,
                        data.Length,
                        IntPtr.Zero,
                        result,
                        result.Length,
                        out var pcbResult,
                        NcryptPadPkcs1Flag);

                    Array.Resize(ref result, pcbResult);
                }
            }

            return result;
        }

        [DllImport("ncrypt.dll")]
        private static extern int NCryptDecrypt(
            SafeNCryptKeyHandle key,
            [In] [MarshalAs(UnmanagedType.LPArray)]
            byte[] input1,
            int input2,
            IntPtr paddingZero,
            [Out] [MarshalAs(UnmanagedType.LPArray)]
            byte[] output1,
            int output2,
            [Out] out int result,
            int flags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptEncrypt(
            SafeNCryptKeyHandle key,
            [In] [MarshalAs(UnmanagedType.LPArray)]
            byte[] input1,
            int input2,
            IntPtr paddingZero,
            [Out] [MarshalAs(UnmanagedType.LPArray)]
            byte[] output1,
            int output2,
            [Out] out int result,
            int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenKey(
            SafeNCryptProviderHandle provider,
            [Out] out SafeNCryptKeyHandle key,
            string keyName,
            int legacyKeySpec,
            CngKeyOpenOptions flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptOpenStorageProvider(
            [Out] out SafeNCryptProviderHandle provider,
            string providerName,
            int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptSetProperty(
            SafeNCryptHandle handle,
            string property,
            string input1,
            int input2,
            CngPropertyOptions flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptSetProperty(
            SafeNCryptHandle handle,
            string property,
            [In] [MarshalAs(UnmanagedType.LPArray)]
            byte[] input1,
            int input2,
            CngPropertyOptions flags);

        [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
        private static extern int NgcGetDefaultDecryptionKeyName(
            string sid,
            int reserved1,
            int reserved2,
            [Out] out string keyName);

        /// <summary>
        ///     Retrieves the name of the passport key.
        /// </summary>
        /// <returns>The name of the passport key.</returns>
        private static string RetrievePassportKeyName()
        {
            NgcGetDefaultDecryptionKeyName(WindowsIdentity.GetCurrent().User?.Value, 0, 0, out var key);
            return key;
        }
    }
}