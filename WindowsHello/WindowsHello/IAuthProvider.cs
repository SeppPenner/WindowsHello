namespace WindowsHello
{
    /// <summary>
    /// This interface is used to abstract different authentication providers.
    /// </summary>
    public interface IAuthProvider
    {
        /// <summary>
        /// Prompts to decrypt the data.
        /// </summary>
        /// <param name="data">The encrypted data.</param>
        /// <returns>The decrypted data as <see cref="T:byte[]"/>.</returns>
        byte[] PromptToDecrypt(byte[] data);

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The decrypted data.</param>
        /// <returns>The encrypted data as <see cref="T:byte[]"/>.</returns>
        byte[] Encrypt(byte[] data);
    }
}