// --------------------------------------------------------------------------------------------------------------------
// <copyright file="EnvironmentErrorException.cs" company="Hämmer Electronics">
//   Copyright (c) 2020 All rights reserved.
// </copyright>
// <summary>
//   The environment error exception.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace WindowsHello.Exceptions;

/// <summary>
///     The environment error exception.
/// </summary>
/// <seealso cref="WindowsHelloException"/>
[Serializable]
public class EnvironmentErrorException : WindowsHelloException
{
    /// <summary>Initializes a new instance of the <see cref="EnvironmentErrorException" /> class.</summary>
    public EnvironmentErrorException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="EnvironmentErrorException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    public EnvironmentErrorException(string message) : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="EnvironmentErrorException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="inner">The inner exception causing this exception.</param>
    public EnvironmentErrorException(string message, Exception inner) : base(message, inner)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="EnvironmentErrorException" /> class.</summary>
    /// <param name="message">The message describing the error.</param>
    /// <param name="errorCode">The error code.</param>
    public EnvironmentErrorException(string message, int errorCode) : this(
        message + "\nError code: " + errorCode.ToString("X"))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EnvironmentErrorException"/> class.
    /// </summary>
    /// <param name="info">The serialization information.</param>
    /// <param name="context">The streaming context.</param>
    protected EnvironmentErrorException(SerializationInfo info, StreamingContext context) : base(info, context)
    {
    }
}
