// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AuthProviderUserCancelledException.cs" company="Hämmer Electronics">
//   Copyright (c) All rights reserved.
// </copyright>
// <summary>
//   The authentication provider system error exception.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Exceptions;

/// <summary>
/// The authentication provider system error exception.
/// </summary>
/// <seealso cref="AuthProviderException" />
[Serializable]
public class AuthProviderUserCancelledException : AuthProviderException
{
    /// <summary>Initializes a new instance of the <see cref="AuthProviderUserCancelledException" /> class.</summary>
    public AuthProviderUserCancelledException() : this("Operation was canceled by user.")
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderUserCancelledException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    public AuthProviderUserCancelledException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderUserCancelledException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="inner">The inner exception causing this exception.</param>
    public AuthProviderUserCancelledException(string message, Exception inner) : base(message, inner)
    {
    }
}
