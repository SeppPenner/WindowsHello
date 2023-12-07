// --------------------------------------------------------------------------------------------------------------------
// <copyright file="WinHelloProvider.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   Defines the WinHelloProvider type.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello;

/// <inheritdoc cref="IAuthProvider" />
/// <summary>
///     This class provides access to the Microsoft Windows Hello
///     (https://support.microsoft.com/de-de/help/17215/windows-10-what-is-hello) functionality.
/// </summary>
public class WinHelloProvider : IAuthProvider
{
    /// <summary>
    ///     The BCrypt RSA algorithm.
    /// </summary>
    private const string BCRYPT_RSA_ALGORITHM = "RSA";

    /// <summary>
    ///     The domain.
    /// </summary>
    private const string Domain = "WindowsHello";

    /// <summary>
    ///     The invalid key message.
    /// </summary>
    private const string InvalidatedKeyMessage =
        "Persistent key has not met integrity requirements. It might be caused by a spoofing attack. Try to recreate the key.";

    /// <summary>
    ///     The Microsoft passport key storage provider.
    /// </summary>
    private const string MS_NGC_KEY_STORAGE_PROVIDER = "Microsoft Passport Key Storage Provider";

    /// <summary>
    /// The NCrypt allow decrypt flag.
    /// </summary>
    private const int NCRYPT_ALLOW_DECRYPT_FLAG = 0x00000001;

    /// <summary>
    /// The NCrypt allow key import flag.
    /// </summary>
    private const int NCRYPT_ALLOW_KEY_IMPORT_FLAG = 0x00000008;

    /// <summary>
    /// The NCrypt allow signing flag.
    /// </summary>
    private const int NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002;

    /// <summary>
    ///     The NCrypt key usage.
    /// </summary>
    private const string NCRYPT_KEY_USAGE_PROPERTY = "Key Usage";

    /// <summary>
    ///     The NCrypt length.
    /// </summary>
    private const string NCRYPT_LENGTH_PROPERTY = "Length";

    /// <summary>
    ///     The NCrypt NGC cache type.
    /// </summary>
    private const string NCRYPT_NGC_CACHE_TYPE_PROPERTY = "NgcCacheType";

    /// <summary>
    /// The NCrypt NGC cache type property auth mandatory flag.
    /// </summary>
    private const int NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG = 0x00000001;

    /// <summary>
    ///     The NCrypt NGC cache type (deprecated).
    /// </summary>
    private const string NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED = "NgcCacheTypeProperty";

    /// <summary>
    /// The NCrypt pad PKCS1 flag.
    /// </summary>
    private const int NCRYPT_PAD_PKCS1_FLAG = 0x00000002;

    /// <summary>
    ///     The NCrypt pin cache is gesture required value.
    /// </summary>
    private const string NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY = "PinCacheIsGestureRequired";

    /// <summary>
    ///     The NCrypt use context.
    /// </summary>
    private const string NCRYPT_USE_CONTEXT_PROPERTY = "Use Context";

    /// <summary>
    ///     The NCrypt window handle.
    /// </summary>
    private const string NCRYPT_WINDOW_HANDLE_PROPERTY = "HWND Handle";

    /// <summary>
    /// The NTE no key.
    /// </summary>
    private const int NTE_NO_KEY = unchecked((int)0x8009000D);

    /// <summary>
    /// The NTE user cancelled.
    /// </summary>
    private const int NTE_USER_CANCELLED = unchecked((int)0x80090036);

    /// <summary>
    ///     The persistent name.
    /// </summary>
    private const string PersistentName = "WindowsHello";

    /// <summary>
    ///     The sub domain.
    /// </summary>
    private const string SubDomain = "";

    /// <summary>
    ///     The local key name.
    /// </summary>
    private static readonly Lazy<string> LocalKeyName = new (RetrieveLocalKeyName);

    /// <summary>
    ///     The mutex.
    /// </summary>
    private static readonly object Mutex = new();

    /// <summary>
    ///     The persistent key name.
    /// </summary>
    private static Lazy<string> persistentKeyName = new(RetrievePersistentKeyName);

    /// <summary>
    ///     The current key name.
    /// </summary>
    private static string currentKeyName = string.Empty;

    /// <summary>
    ///     The Windows hello provider instance.
    /// </summary>
    private static WinHelloProvider? instance;

    /// <summary>
    ///     The authentication provider UI context.
    /// </summary>
    private static AuthProviderUiContext? uiContext;

    /// <summary>
    ///     Initializes a new instance of the <see cref="WinHelloProvider" /> class.
    /// </summary>
    /// <param name="uIContext">The authentication provider UI context.</param>
    private WinHelloProvider(AuthProviderUiContext uIContext)
    {
        if (!TryOpenPersistentKey(out var ngcKeyHandle))
        {
            throw new AuthProviderInvalidKeyException("Persistent key does not exist.");
        }

        using (ngcKeyHandle)
        {
            if (!VerifyPersistentKeyIntegrity(ngcKeyHandle))
            {
                ngcKeyHandle.Close();
                DeletePersistentKey();
                throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);
            }
        }

        uiContext = uIContext;
        currentKeyName = persistentKeyName.Value;
    }

    /// <summary>
    ///     Creates a new instance of the <see cref="WinHelloProvider" /> class.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="windowHandle">The window handle.</param>
    /// <returns>A new instance of the <see cref="WinHelloProvider" /> class.</returns>
    public static WinHelloProvider CreateInstance(string message, IntPtr windowHandle)
    {
        if (!IsAvailable())
        {
            throw new AuthProviderIsUnavailableException("Windows Hello is not available.");
        }

        lock (Mutex)
        {
            if (!TryOpenPersistentKey(out var ngcKeyHandle))
            {
                CreatePersistentKey(true, AuthProviderUiContext.With(message, windowHandle)).Dispose();
            }

            ngcKeyHandle.Dispose();
            var winHelloProvider = new WinHelloProvider(AuthProviderUiContext.With(message, windowHandle));
            return instance ??= winHelloProvider;
        }
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
        byte[] cbResult;
        NCryptOpenStorageProvider(out var ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0)
            .CheckStatus("NCryptOpenStorageProvider");

        using (ngcProviderHandle)
        {
            NCryptOpenKey(ngcProviderHandle, out var ngcKeyHandle, currentKeyName, 0, CngKeyOpenOptions.Silent)
                .CheckStatus("NCryptOpenKey");

            using (ngcKeyHandle)
            {
                if (!VerifyPersistentKeyIntegrity(ngcKeyHandle))
                {
                    throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);
                }

                NCryptEncrypt(
                    ngcKeyHandle,
                    data,
                    data.Length,
                    IntPtr.Zero,
                    null,
                    0,
                    out var pcbResult,
                    NCRYPT_PAD_PKCS1_FLAG).CheckStatus("NCryptEncrypt");

                cbResult = new byte[pcbResult];
                NCryptEncrypt(
                    ngcKeyHandle,
                    data,
                    data.Length,
                    IntPtr.Zero,
                    cbResult,
                    cbResult.Length,
                    out pcbResult,
                    NCRYPT_PAD_PKCS1_FLAG).CheckStatus("NCryptEncrypt");

                Debug.Assert(cbResult.Length == pcbResult, "cbResult.Length == pcbResult");
            }
        }

        return cbResult;
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
        if (uiContext is null)
        {
            throw new ArgumentNullException(nameof(uiContext), "The UI context wasn't set properly.");
        }

        byte[] cbResult;
        NCryptOpenStorageProvider(out var ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0)
            .CheckStatus("NCryptOpenStorageProvider");

        using (ngcProviderHandle)
        {
            NCryptOpenKey(ngcProviderHandle, out var ngcKeyHandle, currentKeyName, 0, CngKeyOpenOptions.None)
                .CheckStatus("NCryptOpenKey");

            using (ngcKeyHandle)
            {
                if (!VerifyPersistentKeyIntegrity(ngcKeyHandle))
                {
                    throw new AuthProviderInvalidKeyException(InvalidatedKeyMessage);
                }

                ApplyUiContext(ngcKeyHandle, uiContext);

                var pinRequired = BitConverter.GetBytes(1);
                NCryptSetProperty(
                    ngcKeyHandle,
                    NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY,
                    pinRequired,
                    pinRequired.Length,
                    CngPropertyOptions.None).CheckStatus("NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY");

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
                    NCRYPT_PAD_PKCS1_FLAG).CheckStatus("NCryptDecrypt");

                // TODO: secure resize
                Array.Resize(ref cbResult, pcbResult);
            }
        }

        return cbResult;
    }

    /// <summary>
    ///     Sets the persistent key name.
    /// </summary>
    /// <param name="persistentName">The persistent name to use.</param>
    public void SetPersistentKeyName(string persistentName)
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        var value = sid + "//" + Domain + "/" + SubDomain + "/"
                    + persistentName.Replace("/", string.Empty).Replace("//", string.Empty);
        persistentKeyName = new Lazy<string>(() => value);
    }

    /// <summary>
    ///     Applies the UI context.
    /// </summary>
    /// <param name="ngcKeyHandle">The safe NCrypt key handle.</param>
    /// <param name="uiContextParam">The authentication provider UI context.</param>
    private static void ApplyUiContext(SafeNCryptHandle ngcKeyHandle, AuthProviderUiContext uiContextParam)
    {
        if (uiContextParam == null)
        {
            return;
        }

        var parentWindowHandle = uiContextParam.ParentWindowHandle;
        if (parentWindowHandle != IntPtr.Zero)
        {
            var handle = BitConverter.GetBytes(
                IntPtr.Size == 8 ? parentWindowHandle.ToInt64() : parentWindowHandle.ToInt32());
            NCryptSetProperty(
                ngcKeyHandle,
                NCRYPT_WINDOW_HANDLE_PROPERTY,
                handle,
                handle.Length,
                CngPropertyOptions.None).CheckStatus("NCRYPT_WINDOW_HANDLE_PROPERTY");
        }

        var message = uiContextParam.Message;
        if (!string.IsNullOrEmpty(message))
        {
            NCryptSetProperty(
                ngcKeyHandle,
                NCRYPT_USE_CONTEXT_PROPERTY,
                message,
                (message.Length + 1) * 2,
                CngPropertyOptions.None).CheckStatus("NCRYPT_USE_CONTEXT_PROPERTY");
        }
    }

    /// <summary>
    ///     Creates a persistent key.
    /// </summary>
    /// <param name="overwriteExisting">
    ///     A <see cref="bool" /> value indicating whether the existing key should be overwritten
    ///     or not.
    /// </param>
    /// <param name="uIContext">The authentication provider UI context.</param>
    /// <returns>A new safe NCrypt key handle.</returns>
    private static SafeNCryptKeyHandle CreatePersistentKey(bool overwriteExisting, AuthProviderUiContext uIContext)
    {
        NCryptOpenStorageProvider(out var ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0)
            .CheckStatus("NCryptOpenStorageProvider");

        SafeNCryptKeyHandle ngcKeyHandle;
        using (ngcProviderHandle)
        {
            NCryptCreatePersistedKey(
                    ngcProviderHandle,
                    out ngcKeyHandle,
                    BCRYPT_RSA_ALGORITHM,
                    persistentKeyName.Value,
                    0,
                    overwriteExisting ? CngKeyCreationOptions.OverwriteExistingKey : CngKeyCreationOptions.None)
                .CheckStatus("NCryptCreatePersistedKey");

            var lengthProp = BitConverter.GetBytes(2048);
            NCryptSetProperty(
                ngcKeyHandle,
                NCRYPT_LENGTH_PROPERTY,
                lengthProp,
                lengthProp.Length,
                CngPropertyOptions.None).CheckStatus("NCRYPT_LENGTH_PROPERTY");

            var keyUsage = BitConverter.GetBytes(NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG);
            NCryptSetProperty(
                ngcKeyHandle,
                NCRYPT_KEY_USAGE_PROPERTY,
                keyUsage,
                keyUsage.Length,
                CngPropertyOptions.None).CheckStatus("NCRYPT_KEY_USAGE_PROPERTY");

            var cacheType = BitConverter.GetBytes(NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG);
            try
            {
                NCryptSetProperty(
                    ngcKeyHandle,
                    NCRYPT_NGC_CACHE_TYPE_PROPERTY,
                    cacheType,
                    cacheType.Length,
                    CngPropertyOptions.None).CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY");
            }
            catch
            {
                NCryptSetProperty(
                    ngcKeyHandle,
                    NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED,
                    cacheType,
                    cacheType.Length,
                    CngPropertyOptions.None).CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED");
            }

            ApplyUiContext(ngcKeyHandle, uIContext);

            NCryptFinalizeKey(ngcKeyHandle, 0).CheckStatus("NCryptFinalizeKey");
        }

        return ngcKeyHandle;
    }

    /// <summary>
    ///     Deletes the persistent key.
    /// </summary>
    private static void DeletePersistentKey()
    {
        if (!TryOpenPersistentKey(out var ngcKeyHandle))
        {
            return;
        }

        using (ngcKeyHandle)
        {
            NCryptDeleteKey(ngcKeyHandle, 0).CheckStatus("NCryptDeleteKey");
            ngcKeyHandle.SetHandleAsInvalid();
        }
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
    /// Creates the NCrypt persistent key.
    /// </summary>
    /// <param name="hProvider">The safe NCrypt provider handle.</param>
    /// <param name="phKey">The safe NCrypt key handle.</param>
    /// <param name="pszAlgId">The algorithm identifier.</param>
    /// <param name="pszKeyName">The PSZ key name.</param>
    /// <param name="dwLegacyKeySpec">The legacy key spec.</param>
    /// <param name="dwFlags">The CNG key creation options.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern SECURITY_STATUS NCryptCreatePersistedKey(
        SafeNCryptProviderHandle hProvider,
        [Out] out SafeNCryptKeyHandle phKey,
        string pszAlgId,
        string pszKeyName,
        int dwLegacyKeySpec,
        CngKeyCreationOptions dwFlags);

    /// <summary>
    /// Decrypts using NCrypt.
    /// </summary>
    /// <param name="hKey">The safe NCrypt key handle.</param>
    /// <param name="pbInput">The input bytes.</param>
    /// <param name="cbInput">The input CB value.</param>
    /// <param name="pvPaddingZero">The zero padding.</param>
    /// <param name="pbOutput">The output bytes.</param>
    /// <param name="cbOutput">The output CB value.</param>
    /// <param name="pcbResult">The result.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
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

    /// <summary>
    /// Deletes the key using NCrypt.
    /// </summary>
    /// <param name="hKey">The safe NCrypt key handle.</param>
    /// <param name="flags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll")]
    private static extern SECURITY_STATUS NCryptDeleteKey(SafeNCryptKeyHandle hKey, int flags);

    /// <summary>
    /// Encrypts using NCrypt.
    /// </summary>
    /// <param name="hKey">The safe NCrypt key handle.</param>
    /// <param name="pbInput">The input bytes.</param>
    /// <param name="cbInput">The input CB value.</param>
    /// <param name="pvPaddingZero">The zero padding.</param>
    /// <param name="pbOutput">The output bytes.</param>
    /// <param name="cbOutput">The output CB value.</param>
    /// <param name="pcbResult">The result.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll")]
    private static extern SECURITY_STATUS NCryptEncrypt(
        SafeNCryptKeyHandle hKey,
        [In] [MarshalAs(UnmanagedType.LPArray)]
        byte[] pbInput,
        int cbInput,
        IntPtr pvPaddingZero,
        [Out] [MarshalAs(UnmanagedType.LPArray)]
        byte[]? pbOutput,
        int cbOutput,
        [Out] out int pcbResult,
        int dwFlags);

    /// <summary>
    /// Finalizes the key using NCrypt.
    /// </summary>
    /// <param name="hKey">The safe NCrypt key handle.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll")]
    private static extern SECURITY_STATUS NCryptFinalizeKey(SafeNCryptKeyHandle hKey, int dwFlags);

    /// <summary>
    /// Gets the property using NCrypt.
    /// </summary>
    /// <param name="hObject">The safe NCrypt handle.</param>
    /// <param name="pszProperty">The PSZ property.</param>
    /// <param name="pbOutput">The output bytes.</param>
    /// <param name="cbOutput">The output CB value.</param>
    /// <param name="pcbResult">The result.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern SECURITY_STATUS NCryptGetProperty(
        SafeNCryptHandle hObject,
        string pszProperty,
        ref int pbOutput,
        int cbOutput,
        [Out] out int pcbResult,
        CngPropertyOptions dwFlags);

    /// <summary>
    /// Opens the key using NCrypt.
    /// </summary>
    /// <param name="hProvider">The safe NCrypt provider handle.</param>
    /// <param name="phKey">The safe NCrypt key handle.</param>
    /// <param name="pszKeyName">The PSZ key name.</param>
    /// <param name="dwLegacyKeySpec">The legacy key spec.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern SECURITY_STATUS NCryptOpenKey(
        SafeNCryptProviderHandle hProvider,
        [Out] out SafeNCryptKeyHandle phKey,
        string pszKeyName,
        int dwLegacyKeySpec,
        CngKeyOpenOptions dwFlags);

    /// <summary>
    /// Opens the storage provider using NCrypt.
    /// </summary>
    /// <param name="phProvider">The safe NCrypt handle.</param>
    /// <param name="pszProviderName">The PSZ provider name.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern SECURITY_STATUS NCryptOpenStorageProvider(
        [Out] out SafeNCryptProviderHandle phProvider,
        string pszProviderName,
        int dwFlags);

    /// <summary>
    /// Sets a property using NCrypt.
    /// </summary>
    /// <param name="hObject">The safe NCrypt handle.</param>
    /// <param name="pszProperty">The PSZ property.</param>
    /// <param name="pbInput">The input bytes.</param>
    /// <param name="cbInput">The input CB value.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern SECURITY_STATUS NCryptSetProperty(
        SafeNCryptHandle hObject,
        string pszProperty,
        string pbInput,
        int cbInput,
        CngPropertyOptions dwFlags);

    /// <summary>
    /// Sets a property using NCrypt.
    /// </summary>
    /// <param name="hObject">The safe NCrypt handle.</param>
    /// <param name="pszProperty">The PSZ property.</param>
    /// <param name="pbInput">The input bytes.</param>
    /// <param name="cbInput">The input CB value.</param>
    /// <param name="dwFlags">The flags.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern SECURITY_STATUS NCryptSetProperty(
        SafeNCryptHandle hObject,
        string pszProperty,
        [In] [MarshalAs(UnmanagedType.LPArray)]
        byte[] pbInput,
        int cbInput,
        CngPropertyOptions dwFlags);

    /// <summary>
    /// Gets the default decryption key name using NCrypt.
    /// </summary>
    /// <param name="pszSid">The PSZ S identifier.</param>
    /// <param name="dwReserved1">The DW reserved 1.</param>
    /// <param name="dwReserved2">The DW reserved 2.</param>
    /// <param name="ppszKeyName">The PPSZ key name.</param>
    /// <returns>A new <see cref="SECURITY_STATUS"/>.</returns>
    [DllImport("cryptngc.dll", CharSet = CharSet.Unicode)]
    private static extern SECURITY_STATUS NgcGetDefaultDecryptionKeyName(
        string pszSid,
        int dwReserved1,
        int dwReserved2,
        [Out] out string ppszKeyName);

    /// <summary>
    ///     Gets the local key name.
    /// </summary>
    /// <returns>The local key name as <see cref="string" />.</returns>
    private static string RetrieveLocalKeyName()
    {
        NgcGetDefaultDecryptionKeyName(WindowsIdentity.GetCurrent().User?.Value ?? string.Empty, 0, 0, out var key);
        return key;
    }

    /// <summary>
    ///     Gets the persistent key name.
    /// </summary>
    /// <returns>The local key name as <see cref="string" />.</returns>
    private static string RetrievePersistentKeyName()
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        return sid + "//" + Domain + "/" + SubDomain + "/" + PersistentName;
    }

    /// <summary>
    ///     Tries to open the persistent key,
    /// </summary>
    /// <param name="ngcKeyHandle">The safe NCrypt key handle.</param>
    /// <returns>A <see cref="bool" /> value indicating whether the handle is valid or not.</returns>
    private static bool TryOpenPersistentKey(out SafeNCryptKeyHandle ngcKeyHandle)
    {
        NCryptOpenStorageProvider(out var ngcProviderHandle, MS_NGC_KEY_STORAGE_PROVIDER, 0)
            .CheckStatus("NCryptOpenStorageProvider");

        using (ngcProviderHandle)
        {
            NCryptOpenKey(ngcProviderHandle, out ngcKeyHandle, persistentKeyName.Value, 0, CngKeyOpenOptions.None)
                .CheckStatus("NCryptOpenKey", NTE_NO_KEY);
        }

        return ngcKeyHandle != null && !ngcKeyHandle.IsInvalid;
    }

    /// <summary>
    ///     Verifies the integrity of the persistent key.
    /// </summary>
    /// <param name="ngcKeyHandle">The safe NCrypt key handle.</param>
    /// <returns>A <see cref="bool" /> value indicating whether the persistent key's integrity is valid or not.</returns>
    private static bool VerifyPersistentKeyIntegrity(SafeNCryptHandle ngcKeyHandle)
    {
        var keyUsage = 0;
        NCryptGetProperty(
            ngcKeyHandle,
            NCRYPT_KEY_USAGE_PROPERTY,
            ref keyUsage,
            sizeof(int),
            out _,
            CngPropertyOptions.None).CheckStatus("NCRYPT_KEY_USAGE_PROPERTY");

        if ((keyUsage & NCRYPT_ALLOW_KEY_IMPORT_FLAG) == NCRYPT_ALLOW_KEY_IMPORT_FLAG)
        {
            return false;
        }

        var cacheType = 0;
        try
        {
            NCryptGetProperty(
                ngcKeyHandle,
                NCRYPT_NGC_CACHE_TYPE_PROPERTY,
                ref cacheType,
                sizeof(int),
                out _,
                CngPropertyOptions.None).CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY");
        }
        catch
        {
            NCryptGetProperty(
                ngcKeyHandle,
                NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED,
                ref cacheType,
                sizeof(int),
                out _,
                CngPropertyOptions.None).CheckStatus("NCRYPT_NGC_CACHE_TYPE_PROPERTY_DEPRECATED");
        }

        return cacheType == NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_STATUS
    {
        /// <summary>
        /// The security status.
        /// </summary>
        private readonly int secStatus;

        /// <summary>
        /// Checks the status.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <param name="ignoreStatus">A <see cref="bool"/> value indicating whether the status is ignored or not</param>
        public void CheckStatus(string name = "", int ignoreStatus = 0)
        {
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

            if (this.secStatus >= 0 || this.secStatus == ignoreStatus)
            {
                return;
            }

            throw this.secStatus switch
            {
                NTE_USER_CANCELLED => new AuthProviderUserCancelledException(),
                _ => new AuthProviderSystemErrorException(name, this.secStatus)
            };
        }
    }
}

/// <inheritdoc cref="IWin32Window" />
/// <summary>
///     The authentication provider UI context.
/// </summary>
/// <seealso cref="IWin32Window" />
internal sealed class AuthProviderUiContext : IWin32Window
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="AuthProviderUiContext" /> class.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="windowHandle">The window handle.</param>
    private AuthProviderUiContext(string message, IntPtr windowHandle)
    {
        this.Message = message;
        this.ParentWindowHandle = windowHandle;
    }

    /// <summary>
    ///     Gets the message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    ///     Gets the parent window handle.
    /// </summary>
    public IntPtr ParentWindowHandle { get; }

    /// <summary>
    ///     Gets the handle.
    /// </summary>
    IntPtr IWin32Window.Handle => this.ParentWindowHandle;

    /// <summary>
    ///     A handler method to use the authentication UI context.
    /// </summary>
    /// <param name="message">The message.</param>
    /// <param name="windowHandle">The window handle.</param>
    /// <returns>A new authentication UI context.</returns>
    public static AuthProviderUiContext With(string message, IntPtr windowHandle)
    {
        return new AuthProviderUiContext(message, windowHandle);
    }
}
