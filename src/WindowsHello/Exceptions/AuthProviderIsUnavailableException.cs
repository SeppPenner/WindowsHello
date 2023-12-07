// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AuthProviderIsUnavailableException.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The authentication provider unavailable exception.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Exceptions;

/// <summary>
/// The authentication provider unavailable exception.
/// </summary>
/// <seealso cref="AuthProviderException" />
[Serializable]
public class AuthProviderIsUnavailableException : AuthProviderException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthProviderIsUnavailableException"/> class.
    /// </summary>
    public AuthProviderIsUnavailableException() : this("Authentication provider is not available.")
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthProviderIsUnavailableException"/> class.
    /// </summary>
    /// <param name="message">The message describing the error.</param>
    public AuthProviderIsUnavailableException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthProviderIsUnavailableException"/> class.
    /// </summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="inner">The inner exception causing this exception.</param>
    public AuthProviderIsUnavailableException(string message, Exception inner) : base(message, inner)
    {
    }
}
