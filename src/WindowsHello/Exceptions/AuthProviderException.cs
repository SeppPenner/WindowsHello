// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AuthProviderException.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The authentication provider exception.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Exceptions;

/// <summary>
///     The authentication provider exception.
/// </summary>
/// <seealso cref="WindowsHelloException" />
[Serializable]
public class AuthProviderException : WindowsHelloException
{
    /// <summary>Initializes a new instance of the <see cref="AuthProviderException" /> class.</summary>
    public AuthProviderException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    public AuthProviderException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="inner">The inner exception causing this exception.</param>
    public AuthProviderException(string message, Exception inner) : base(message, inner)
    {
    }
}
