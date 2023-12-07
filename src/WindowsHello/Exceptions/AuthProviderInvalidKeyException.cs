// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AuthProviderInvalidKeyException.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The authentication provider invalid key exception.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Exceptions;

/// <summary>
///     The authentication provider invalid key exception.
/// </summary>
/// <seealso cref="AuthProviderException" />
[Serializable]
public class AuthProviderInvalidKeyException : AuthProviderException
{
    /// <summary>Initializes a new instance of the <see cref="AuthProviderInvalidKeyException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    public AuthProviderInvalidKeyException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthProviderInvalidKeyException"/> class.
    /// </summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="inner">The inner exception causing this exception.</param>
    public AuthProviderInvalidKeyException(string message, Exception inner) : base(message, inner)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderInvalidKeyException" /> class.</summary>
    protected AuthProviderInvalidKeyException()
    {
    }
}
