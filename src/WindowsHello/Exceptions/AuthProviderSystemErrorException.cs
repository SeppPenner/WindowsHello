// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AuthProviderSystemErrorException.cs" company="Hämmer Electronics">
//   Copyright (c) 2020 All rights reserved.
// </copyright>
// <summary>
//   The authentication provider system error exception.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Exceptions;

/// <summary>
/// The authentication provider system error exception.
/// </summary>
/// <seealso cref="EnvironmentErrorException" />
[Serializable]
public class AuthProviderSystemErrorException : EnvironmentErrorException
{
    /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
    public AuthProviderSystemErrorException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="errorCode">The error code.</param>
    public AuthProviderSystemErrorException(string message, int errorCode) : base(message, errorCode)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    public AuthProviderSystemErrorException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="AuthProviderSystemErrorException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="inner">The inner exception causing this exception.</param>
    public AuthProviderSystemErrorException(string message, Exception inner) : base(message, inner)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthProviderSystemErrorException"/> class.
    /// </summary>
    /// <param name="info">The serialization information.</param>
    /// <param name="context">The streaming context.</param>
    protected AuthProviderSystemErrorException(
        SerializationInfo info,
        StreamingContext context) : base(info, context)
    {
    }
}
