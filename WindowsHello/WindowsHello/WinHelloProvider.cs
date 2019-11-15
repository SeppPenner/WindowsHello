using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Windows.Forms;
using WindowsHello.Exceptions;
using Microsoft.Win32.SafeHandles;

namespace WindowsHello
{
    /// <inheritdoc cref="IAuthProvider"/>
    /// <summary>
    ///     This class provides access to the Microsoft Windows Hello
    ///     (https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) functionality.
    /// </summary>
    public class WinHelloProvider : IAuthProvider
    {
        private const string Domain = "WindowsHello";
        private const string SubDomain = "";
        private const string PersistentName = "WindowsHello";

        private const string InvalidatedKeyMessage =
            "Persistent key has not met integrity requirements. It might be caused by a spoofing attack. Try to recreate the key.";

        private static readonly Lazy<string> LocalKeyName = new Lazy<string>(RetrieveLocalKeyName);
        private static Lazy<string> _persistentKeyName = new Lazy<string>(RetrievePersistentKeyName);

        private static readonly object Mutex = new object();
        private static WinHelloProvider _instance;
        private static string _currentKeyName;
        private static AuthProviderUiContext _uiContext;

        private WinHelloProvider(AuthProviderUiContext uIContext)
        {
            if (!TryOpenPersistentKey(out var ngcKeyHandle))
                throw new AuthProviderInvalidKeyException("Persistent key does not exist.");

            using (ngcKeyHandle)
            {
                if (!VerifyPersistentKeyIntegrity(ngcKeyHandle))
                {
                    ngcKeyHandle.Close();
                    DeletePersistentKey();
                    throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);
                }
            }

            _uiContext = uIContext;
            _currentKeyName = _persistentKeyName.Value;
        }

        /// <inheritdoc cref="IAuthProvider"/>
        /// <summary>
        ///     Encrypts the specified data.
        /// </summary>
        /// <param name="data">The decrypted data.</param>
        /// <returns>
        ///     The encrypted data as <see cref="T:byte[]" />.
        /// </returns>
        /// <exception cref="NotSupportedException">Windows Hello is not available</exception>
        // ReSharper disable once UnusedMember.Global
        public byte[] Encrypt(byte[] data)
        {
            byte[] cbResult;
            NCryptOpenStorageProvider(
                    out var ngcProviderHandle,
                    MS_NGC_KEY_STORAGE_PROVIDER,
                    0)
                .CheckStatus("NCryptOpenStorageProvider");

            using (ngcProviderHandle)
            {
                NCryptOpenKey(
                        ngcProviderHandle,
                        out var ngcKeyHandle,
                        _currentKeyName,
                        0,
                        CngKeyOpenOptions.Silent)
                    .CheckStatus("NCryptOpenKey");

                using (ngcKeyHandle)
                {
                    if (!VerifyPersistentKeyIntegrity(ngcKeyHandle))
                        throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);

                    NCryptEncrypt(
                            ngcKeyHandle,
                            data,
                            data.Length,
                            IntPtr.Zero,
                            null,
                            0,
                            out var pcbResult,
                            NCRYPT_PAD_PKCS1_FLAG)
                        .CheckStatus("NCryptEncrypt");

                    cbResult = new byte[pcbResult];
                    NCryptEncrypt(
                            ngcKeyHandle,
                            data,
                            data.Length,
                            IntPtr.Zero,
                            cbResult,
                            cbResult.Length,
                            out pcbResult,
                            NCRYPT_PAD_PKCS1_FLAG)
                        .CheckStatus("NCryptEncrypt");

                    Debug.Assert(cbResult.Length == pcbResult);
                }
            }

            return cbResult;
        }

        /// <inheritdoc cref="IAuthProvider"/>
        /// <summary>
        ///     Prompts to decrypt the data.
        /// </summary>
        /// <param name="data">The encrypted data.</param>
        /// <returns>
        ///     The decrypted data as <see cref="T:byte[]" />.
        /// </returns>
        /// <exception cref="T:System.NotSupportedException">Windows Hello is not available</exception>
        // ReSharper disable once UnusedMember.Global
        public byte[] PromptToDecrypt(byte[] data)
        {
            byte[] cbResult;
            NCryptOpenStorageProvider(
                    out var ngcProviderHandle,
                    MS_NGC_KEY_STORAGE_PROVIDER,
                    0)
                .CheckStatus("NCryptOpenStorageProvider");

            using (ngcProviderHandle)
            {
                NCryptOpenKey(
                        ngcProviderHandle,
                        out var ngcKeyHandle,
                        _currentKeyName,
                        0,
                        CngKeyOpenOptions.None)
                    .CheckStatus("NCryptOpenKey");

                using (ngcKeyHandle)
                {
                    if (!VerifyPersistentKeyIntegrity(ngcKeyHandle))
                        throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);

                    ApplyUiContext(ngcKeyHandle, _uiContext);

                    var pinRequired = BitConverter.GetBytes(1);
                    NCryptSetProperty(
                            ngcKeyHandle,
                            NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY,
                            pinRequired,
                            pinRequired.Length,
                            CngPropertyOptions.None)
                        .CheckStatus("NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY");

                    // The pbInput and pbOutput parameters can point to the same buffer. In this case, this function will perform the decryption in place.
                    cbResult = new byte[data.Length * 2];
                    NCryptDecrypt(
                            ngcKeyHandle,
                            data,
                            data.Length,
                            IntPtr.Zero,
                            cbResult,
                            cbResult.Length,
                            out var pcbResult,
                            NCRYPT_PAD_PKCS1_FLAG)
                        .CheckStatus("NCryptDecrypt");
                    // TODO: secure resize
                    Array.Resize(ref cbResult, pcbResult);
                }
            }

            return cbResult;
        }

        /// <summary>
        /// Sets the persistent key name.
        /// </summary>
        /// <param name="persistentName">The persistent name to use.</param>
        /// <returns>The local key name as <see cref="string"/>.</returns>
        // ReSharper disable once UnusedMember.Global
        public void SetPersistentKeyName(string persistentName)
        {
            var sid = WindowsIdentity.GetCurrent().User?.Value;
            var value = sid + "//" + Domain + "/" + SubDomain + "/" + persistentName.Replace("/", "").Replace("//", "");
            _persistentKeyName = new Lazy<string>(() => value);
        }

        /// <summary>
        /// Gets the local key name.
        /// </summary>
        /// <returns>The local key name as <see cref="string"/>.</returns>
        private static string RetrieveLocalKeyName()
        {
            NgcGetDefaultDecryptionKeyName(WindowsIdentity.GetCurrent().User?.Value, 0, 0, out var key);
            return key;
        }

        /// <summary>
        /// Gets the persistent key name.
        /// </summary>
        /// <returns>The local key name as <see cref="string"/>.</returns>
        private static string RetrievePersistentKeyName()
        {
            var sid = WindowsIdentity.GetCurrent().User?.Value;
            return sid + "//" + Domain + "/" + SubDomain + "/" + PersistentName;
        }

        /// <summary>
        ///     Determines whether this instance is available.
        /// </summary>
        /// <returns>
        ///     <c>true</c> if this instance is available; otherwise, <c>false</c>.
        /// </returns>
        private static bool IsAvailable()
        {
            return !string.IsNullOrEmpty(LocalKeyName.Value);
        }

        /// <summary>
        /// Creates a new instance of the <see cref="WinHelloProvider"/> class.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="windowHandle">The window handle.</param>
        /// <returns>A new instance of the <see cref="WinHelloProvider"/> class.</returns>
        // ReSharper disable once UnusedMember.Global
        public static WinHelloProvider CreateInstance(string message, IntPtr windowHandle)
        {
            if (!IsAvailable())
                throw new AuthProviderIsUnavailableException("Windows Hello is not available.");

            lock (Mutex)
            {
                if (!TryOpenPersistentKey(out var ngcKeyHandle))
                    CreatePersistentKey(true, AuthProviderUiContext.With(message, windowHandle)).Dispose();

                ngcKeyHandle.Dispose();
                var winHelloProvider = new WinHelloProvider(AuthProviderUiContext.With(message, windowHandle));
                return _instance ?? (_instance = winHelloProvider);
            }
        }

        private static bool TryOpenPersistentKey(out SafeNCryptKeyHandle ngcKeyHandle)
        {
            NCryptOpenStorageProvider(
                    out var ngcProviderHandle,
                    MS_NGC_KEY_STORAGE_PROVIDER,
                    0)
                .CheckStatus("NCryptOpenStorageProvider");

            using (ngcProviderHandle)
            {
                NCryptOpenKey(ngcProviderHandle,
                    out ngcKeyHandle,
                    _persistentKeyName.Value,
                    0, CngKeyOpenOptions.None
                ).CheckStatus("NCryptOpenKey", NTE_NO_KEY);
            }

            return ngcKeyHandle != null && !ngcKeyHandle.IsInvalid;
        }

        private static bool VerifyPersistentKeyIntegrity(SafeNCryptHandle ngcKeyHandle)
        {
            var keyUsage = 0;
            NCryptGetProperty(ngcKeyHandle,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    ref keyUsage,
                    sizeof(int),
                    out _,
                    CngPropertyOptions.None)
                .CheckStatus("NCRYPT_KEY_USAGE_PROPERTY");

            if ((keyUsage & NCRYPT_ALLOW_KEY_IMPORT_FLAG) == NCRYPT_ALLOW_KEY_IMPORT_FLAG)
                return false;

            var cacheType = 0;
            try
            {
                NCryptGetProperty(
                        ngcKeyHandle,
                        NCRYPT_NGC_CACHE_TYPE_PROPERTY,
                        ref cacheType,
                        sizeof(int),
                        out _,
                        CngPropertyOptions.None)
                    .CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY");
            }
            catch
            {
                NCryptGetProperty(
                        ngcKeyHandle,
                        NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED,
                        ref cacheType,
                        sizeof(int),
                        out _,
                        CngPropertyOptions.None)
                    .CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED");
            }

            return cacheType == NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG;
        }

        private static void DeletePersistentKey()
        {
            if (!TryOpenPersistentKey(out var ngcKeyHandle)) return;
            using (ngcKeyHandle)
            {
                NCryptDeleteKey(ngcKeyHandle, 0).CheckStatus("NCryptDeleteKey");
                ngcKeyHandle.SetHandleAsInvalid();
            }
        }

        /// <summary>
        /// Applies the UI context.
        /// </summary>
        /// <param name="ngcKeyHandle">The NGC key handle.</param>
        /// <param name="uiContext">The UI context.</param>
        private static void ApplyUiContext(SafeNCryptHandle ngcKeyHandle, AuthProviderUiContext uiContext)
        {
            if (uiContext == null) return;
            var parentWindowHandle = uiContext.ParentWindowHandle;
            if (parentWindowHandle != IntPtr.Zero)
            {
                var handle = BitConverter.GetBytes(IntPtr.Size == 8
                    ? parentWindowHandle.ToInt64()
                    : parentWindowHandle.ToInt32());
                NCryptSetProperty(
                        ngcKeyHandle,
                        NCRYPT_WINDOW_HANDLE_PROPERTY,
                        handle,
                        handle.Length,
                        CngPropertyOptions.None)
                    .CheckStatus("NCRYPT_WINDOW_HANDLE_PROPERTY");
            }

            var message = uiContext.Message;
            if (!string.IsNullOrEmpty(message))
                NCryptSetProperty(
                        ngcKeyHandle,
                        NCRYPT_USE_CONTEXT_PROPERTY,
                        message,
                        (message.Length + 1) * 2,
                        CngPropertyOptions.None)
                    .CheckStatus("NCRYPT_USE_CONTEXT_PROPERTY");
        }

        private static SafeNCryptKeyHandle CreatePersistentKey(bool overwriteExisting, AuthProviderUiContext uIContext)
        {
            NCryptOpenStorageProvider(
                out var ngcProviderHandle,
                MS_NGC_KEY_STORAGE_PROVIDER,
                0).CheckStatus("NCryptOpenStorageProvider");

            SafeNCryptKeyHandle ngcKeyHandle;
            using (ngcProviderHandle)
            {
                NCryptCreatePersistedKey(
                        ngcProviderHandle,
                        out ngcKeyHandle,
                        BCRYPT_RSA_ALGORITHM,
                        _persistentKeyName.Value,
                        0,
                        overwriteExisting ? CngKeyCreationOptions.OverwriteExistingKey : CngKeyCreationOptions.None)
                    .CheckStatus("NCryptCreatePersistedKey");

                var lengthProp = BitConverter.GetBytes(2048);
                NCryptSetProperty(
                        ngcKeyHandle,
                        NCRYPT_LENGTH_PROPERTY,
                        lengthProp,
                        lengthProp.Length,
                        CngPropertyOptions.None)
                    .CheckStatus("NCRYPT_LENGTH_PROPERTY");

                var keyUsage = BitConverter.GetBytes(NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG);
                NCryptSetProperty(
                        ngcKeyHandle,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        keyUsage,
                        keyUsage.Length,
                        CngPropertyOptions.None)
                    .CheckStatus("NCRYPT_KEY_USAGE_PROPERTY");

                var cacheType = BitConverter.GetBytes(NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG);
                try
                {
                    NCryptSetProperty(
                            ngcKeyHandle,
                            NCRYPT_NGC_CACHE_TYPE_PROPERTY,
                            cacheType,
                            cacheType.Length,
                            CngPropertyOptions.None)
                        .CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY");
                }
                catch
                {
                    NCryptSetProperty(
                            ngcKeyHandle,
                            NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED,
                            cacheType,
                            cacheType.Length,
                            CngPropertyOptions.None)
                        .CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED");
                }

                ApplyUiContext(ngcKeyHandle, uIContext);

                NCryptFinalizeKey(ngcKeyHandle, 0).CheckStatus("NCryptFinalizeKey");
            }

            return ngcKeyHandle;
        }

        #region CNG key storage provider API

        // ReSharper disable once InconsistentNaming
        private const string MS_NGC_KEY_STORAGE_PROVIDER = "Microsoft Passport Key Storage Provider";
        // ReSharper disable once InconsistentNaming
        private const string NCRYPT_WINDOW_HANDLE_PROPERTY = "HWND Handle";
        // ReSharper disable once InconsistentNaming
        private const string NCRYPT_USE_CONTEXT_PROPERTY = "Use Context";
        // ReSharper disable once InconsistentNaming
        private const string NCRYPT_LENGTH_PROPERTY = "Length";
        // ReSharper disable once InconsistentNaming
        private const string NCRYPT_KEY_USAGE_PROPERTY = "Key Usage";
        // ReSharper disable once InconsistentNaming
        private const string NCRYPT_NGC_CACHE_TYPE_PROPERTY = "NgcCacheType";
        // ReSharper disable once InconsistentNaming
        private const string NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED = "NgcCacheTypeProperty";
        // ReSharper disable once InconsistentNaming
        private const string NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY = "PinCacheIsGestureRequired";
        // ReSharper disable once InconsistentNaming
        private const string BCRYPT_RSA_ALGORITHM = "RSA";
        // ReSharper disable once InconsistentNaming
        private const int NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG = 0x00000001;
        // ReSharper disable once InconsistentNaming
        private const int NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001;
        // ReSharper disable once InconsistentNaming
        private const int NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002;
        // ReSharper disable once InconsistentNaming
        private const int NCRYPT_ALLOW_KEY_IMPORT_FLAG = 0x00000008;
        // ReSharper disable once InconsistentNaming
        private const int NCRYPT_PAD_PKCS1_FLAG = 0x00000002;
        // ReSharper disable once InconsistentNaming
        private const int NTE_USER_CANCELLED = unchecked((int) 0x80090036);
        // ReSharper disable once InconsistentNaming
        private const int NTE_NO_KEY = unchecked((int) 0x8009000D);

        [StructLayout(LayoutKind.Sequential)]
        // ReSharper disable once InconsistentNaming
        private struct SECURITY_STATUS
        {
            private readonly int secStatus;

            /*
            * NTE_BAD_FLAGS
            * NTE_BAD_KEYSET
            * NTE_BAD_KEY_STATE
            * NTE_BUFFER_TOO_SMALL
            * NTE_INVALID_HANDLE
            * NTE_INVALID_PARAMETER
            * NTE_PERM
            * NTE_NO_MEMORY
            * NTE_NOT_SUPPORTED
            * NTE_USER_CANCELLED
            */
            public void CheckStatus(string name = "", int ignoreStatus = 0)
            {
                if (secStatus >= 0 || secStatus == ignoreStatus)
                    return;

                switch (secStatus)
                {
                    case NTE_USER_CANCELLED:
                        throw new AuthProviderUserCancelledException();
                    default:
                        throw new AuthProviderSystemErrorException(name, secStatus);
                }
            }
        }

        [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NgcGetDefaultDecryptionKeyName(
            string pszSid,
            int dwReserved1,
            int dwReserved2,
            [Out] out string ppszKeyName);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptOpenStorageProvider(
            [Out] out SafeNCryptProviderHandle phProvider,
            string pszProviderName,
            int dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptOpenKey(
            SafeNCryptProviderHandle hProvider,
            [Out] out SafeNCryptKeyHandle phKey,
            string pszKeyName,
            int dwLegacyKeySpec,
            CngKeyOpenOptions dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptCreatePersistedKey(
            SafeNCryptProviderHandle hProvider,
            [Out] out SafeNCryptKeyHandle phKey,
            string pszAlgId,
            string pszKeyName,
            int dwLegacyKeySpec,
            CngKeyCreationOptions dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptFinalizeKey(
            SafeNCryptKeyHandle hKey,
            int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptDeleteKey(
            SafeNCryptKeyHandle hKey,
            int flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptGetProperty(
            SafeNCryptHandle hObject,
            string pszProperty,
            ref int pbOutput,
            int cbOutput,
            [Out] out int pcbResult,
            CngPropertyOptions dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptSetProperty(
            SafeNCryptHandle hObject,
            string pszProperty,
            string pbInput,
            int cbInput,
            CngPropertyOptions dwFlags);


        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern SECURITY_STATUS NCryptSetProperty(
            SafeNCryptHandle hObject,
            string pszProperty,
            [In] [MarshalAs(UnmanagedType.LPArray)]
            byte[] pbInput,
            int cbInput,
            CngPropertyOptions dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptEncrypt(
            SafeNCryptKeyHandle hKey,
            [In] [MarshalAs(UnmanagedType.LPArray)]
            byte[] pbInput,
            int cbInput,
            IntPtr pvPaddingZero,
            [Out] [MarshalAs(UnmanagedType.LPArray)]
            byte[] pbOutput,
            int cbOutput,
            [Out] out int pcbResult,
            int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern SECURITY_STATUS NCryptDecrypt(
            SafeNCryptKeyHandle hKey,
            [In] [MarshalAs(UnmanagedType.LPArray)]
            byte[] pbInput,
            int cbInput,
            IntPtr pvPaddingZero,
            [Out] [MarshalAs(UnmanagedType.LPArray)]
            byte[] pbOutput,
            int cbOutput,
            [Out] out int pcbResult,
            int dwFlags);

        #endregion
    }

    internal sealed class AuthProviderUiContext : IWin32Window
    {
        private AuthProviderUiContext(string message, IntPtr windowHandle)
        {
            Message = message;
            ParentWindowHandle = windowHandle;
        }

        public string Message { get; }
        public IntPtr ParentWindowHandle { get; }

        IntPtr IWin32Window.Handle => ParentWindowHandle;

        public static AuthProviderUiContext With(string message, IntPtr windowHandle)
        {
            return new AuthProviderUiContext(message, windowHandle);
        }
    }
}